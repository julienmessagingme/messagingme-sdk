/** L'adresse de l'API en production. */
export const DEFAULT_BASE_URL = 'https://api.messagingme.app';
// ---------------------------------------------------------------------------------------------------------------------
// Les erreurs.
// ---------------------------------------------------------------------------------------------------------------------
/** Une réponse hors 2xx. `code` est `null` sur une panne générique (JSON illisible, erreur interne, réponse non JSON). */
export class ApiError extends Error {
    status;
    code;
    retryAfter;
    upgradeUrl;
    body;
    name = 'ApiError';
    constructor(status, code, message, 
    /** Secondes à attendre avant de réessayer (`Retry-After`), sur un 429 surtout ; `null` si l'API ne le dit pas. */
    retryAfter, 
    /** Sur un 402 : la page où l'offre se change. */
    upgradeUrl, 
    /** Le corps reçu, tel quel (l'objet JSON, ou le texte s'il n'en était pas un). */
    body) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfter = retryAfter;
        this.upgradeUrl = upgradeUrl;
        this.body = body;
    }
}
/** `Retry-After` en secondes : un nombre, ou une date HTTP. */
function secondesAAttendre(valeur, maintenant) {
    if (valeur === null)
        return null;
    const v = valeur.trim();
    if (/^\d+$/.test(v))
        return Number(v);
    const date = Date.parse(v);
    return Number.isNaN(date) ? null : Math.max(0, Math.ceil((date - maintenant) / 1000));
}
async function erreurDe(res) {
    const texte = await res.text().catch(() => '');
    let corps = texte;
    try {
        corps = texte === '' ? null : JSON.parse(texte);
    }
    catch { /* le texte tel quel */ }
    const objet = typeof corps === 'object' && corps !== null ? corps : null;
    const message = typeof objet?.error === 'string' ? objet.error : `HTTP ${res.status}${texte !== '' && objet === null ? ` : ${texte.slice(0, 200)}` : ''}`;
    return new ApiError(res.status, typeof objet?.code === 'string' ? objet.code : null, message, secondesAAttendre(res.headers.get('retry-after'), Date.now()), typeof objet?.upgradeUrl === 'string' ? objet.upgradeUrl : null, corps);
}
/** `/v1/contacts/{contactId}` et `{ contactId }` : chaque paramètre encodé, un paramètre manquant est une erreur. */
function remplirChemin(chemin, params) {
    return chemin.replace(/\{(\w+)\}/g, (_, nom) => {
        const v = params?.[nom];
        if (v === undefined)
            throw new TypeError(`paramètre de chemin manquant : ${nom}`);
        return encodeURIComponent(String(v));
    });
}
export function createClient(options) {
    if (typeof options.apiKey !== 'string' || options.apiKey.trim() === '')
        throw new TypeError('apiKey requise');
    const base = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    const appelerFetch = options.fetch ?? ((entree, init) => fetch(entree, init));
    async function appeler(methode, chemin, o = {}) {
        const url = new URL(base + remplirChemin(chemin, o.path));
        for (const [cle, valeur] of Object.entries(o.query ?? {}))
            if (valeur !== undefined)
                url.searchParams.set(cle, String(valeur));
        const entetes = new Headers(o.headers);
        entetes.set('authorization', `Bearer ${options.apiKey}`);
        entetes.set('accept', 'application/json');
        if (o.idempotencyKey !== undefined)
            entetes.set('idempotency-key', o.idempotencyKey);
        let corps;
        if (o.body !== undefined) {
            entetes.set('content-type', 'application/json');
            corps = JSON.stringify(o.body);
        }
        const res = await appelerFetch(url, { method: methode, headers: entetes, body: corps, ...(o.signal ? { signal: o.signal } : {}) });
        if (!res.ok)
            throw await erreurDe(res);
        if (res.status === 204)
            return undefined;
        return (res.headers.get('content-type') ?? '').includes('json') ? res.json() : res.blob();
    }
    // Une seule implémentation, quatre signatures typées : les types disent ce que chaque route accepte et rend.
    const methode = (m) => (chemin, o) => appeler(m, chemin, o);
    return { GET: methode('GET'), POST: methode('POST'), PATCH: methode('PATCH'), DELETE: methode('DELETE') };
}
/** La signature est absente, fausse, trop vieille, ou le corps n'est pas un événement. */
export class WebhookVerificationError extends Error {
    name = 'WebhookVerificationError';
}
const TOLERANCE_DEFAUT_S = 300;
/** Un HMAC-SHA256 fait 32 octets : une signature d'une autre longueur ne peut pas être la nôtre. */
const OCTETS_SIGNATURE = 32;
/**
 * Au plus tant de signatures examinées : nous en envoyons une, deux pendant une rotation. Sans plafond, un en-tête
 * rempli de candidates ferait calculer un HMAC du corps par candidate, sans connaître aucun secret.
 */
const MAX_SIGNATURES = 10;
function entete(headers, nom) {
    if (typeof headers.get === 'function')
        return headers.get(nom);
    const brut = Object.entries(headers)
        .find(([cle]) => cle.toLowerCase() === nom)?.[1];
    if (brut === undefined)
        return null;
    return typeof brut === 'string' ? brut : brut.join(' ');
}
function octetsDuBase64(b64) {
    const binaire = atob(b64);
    const out = new Uint8Array(new ArrayBuffer(binaire.length));
    for (let i = 0; i < binaire.length; i += 1)
        out[i] = binaire.charCodeAt(i);
    return out;
}
/**
 * Les clés des secrets. Un secret vide ou illisible est une erreur de CONFIGURATION de l'intégrateur, pas une
 * signature fausse : `TypeError`, pour qu'elle se voie (un 500 chez lui) au lieu de se confondre avec un 401.
 */
function clesDesSecrets(secret) {
    const secrets = typeof secret === 'string' ? [secret] : secret;
    if (secrets.length === 0)
        throw new TypeError('secret requis');
    return secrets.map((s) => {
        let cle;
        try {
            cle = octetsDuBase64(s.startsWith('whsec_') ? s.slice('whsec_'.length) : s);
        }
        catch {
            throw new TypeError('secret illisible : attendu whsec_ suivi de base64');
        }
        if (cle.length === 0)
            throw new TypeError('secret vide');
        return cle;
    });
}
/**
 * Vérifie un événement reçu (Standard Webhooks) et le rend typé. Lève `WebhookVerificationError` si la signature ne
 * correspond à aucun secret, si l'horodatage sort de la tolérance, ou si le corps n'est pas un événement ; `TypeError`
 * sur une erreur de configuration (secret vide ou illisible, tolérance qui n'est pas un nombre).
 *
 * La comparaison se fait par `subtle.verify`, en temps constant. Un même événement peut être reçu deux fois (réessai,
 * rejeu dans la fenêtre) : dédoublonner par `webhook-id`.
 */
export async function verifyWebhook(o) {
    const tolerance = o.toleranceSeconds ?? TOLERANCE_DEFAUT_S;
    if (!Number.isFinite(tolerance) || tolerance < 0)
        throw new TypeError('toleranceSeconds : un nombre de secondes, positif ou nul');
    const maintenant = o.now ?? Date.now();
    if (!Number.isFinite(maintenant))
        throw new TypeError('now : un horodatage en millisecondes');
    const cles = clesDesSecrets(o.secret);
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined)
        throw new TypeError('Web Crypto indisponible : Node 20 ou plus, Deno, Bun ou Workers');
    const id = entete(o.headers, 'webhook-id');
    const horodatage = entete(o.headers, 'webhook-timestamp');
    const signatures = entete(o.headers, 'webhook-signature');
    if (id === null || horodatage === null || signatures === null)
        throw new WebhookVerificationError('en-têtes webhook-id, webhook-timestamp ou webhook-signature absents');
    if (!/^\d+$/.test(horodatage))
        throw new WebhookVerificationError('webhook-timestamp illisible');
    if (Math.abs(maintenant / 1000 - Number(horodatage)) > tolerance)
        throw new WebhookVerificationError('horodatage hors tolérance : événement trop ancien ou rejoué');
    // La préimage porte sur les octets REÇUS : un corps en octets n'est ni décodé ni réencodé avant d'être signé.
    const corps = typeof o.body === 'string' ? new TextEncoder().encode(o.body) : o.body;
    const prefixe = new TextEncoder().encode(`${id}.${horodatage}.`);
    const signe = new Uint8Array(prefixe.length + corps.length);
    signe.set(prefixe);
    signe.set(corps, prefixe.length);
    const vues = new Set();
    const recues = [];
    for (const s of signatures.split(' ')) {
        const [version, valeur] = s.split(',');
        if (version !== 'v1' || valeur === undefined || vues.has(valeur))
            continue;
        vues.add(valeur);
        let octets;
        try {
            octets = octetsDuBase64(valeur);
        }
        catch {
            continue;
        }
        if (octets.length === OCTETS_SIGNATURE)
            recues.push(octets);
        if (recues.length === MAX_SIGNATURES)
            break;
    }
    for (const cle of cles) {
        const k = await subtle.importKey('raw', cle, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        for (const recue of recues)
            if (await subtle.verify('HMAC', k, recue, signe))
                return lireEvenement(corps);
    }
    throw new WebhookVerificationError('signature invalide');
}
function lireEvenement(octets) {
    let v;
    try {
        v = JSON.parse(new TextDecoder().decode(octets));
    }
    catch {
        throw new WebhookVerificationError('corps illisible');
    }
    const e = v;
    if (e === null || typeof e !== 'object' || typeof e.id !== 'string' || typeof e.type !== 'string' || typeof e.data !== 'object') {
        throw new WebhookVerificationError('corps signé qui n’est pas un événement');
    }
    return v;
}
