import Axios, {
    AxiosResponse,
    AxiosRequestConfig
} from 'axios';
import {
    v4 as uuidv4
} from 'uuid';
import * as Forge from 'node-forge';
import * as LZString from 'lz-string';
import * as querystring from 'query-string';
import * as cheerio from 'cheerio';

class Naver {
    protected id: string;
    protected password: string;
    private cookies: NaverCookies = {
        nid_inf: null,
        NID_AUT: null,
        NID_SES: null,
        NID_JKL: null
    }

    /**
     * 
     * @param id ID to login in Naver
     * @param password PASSWORD to login in Naver
     * @constructor
     */
    constructor(id: string, password: string) {
        this.id = id;
        this.password = password;
    }

    /**
     * 
     * @param modulus Modulus
     * @param exponent Exponent
     * @returns PublicKey
     * @private
     */
    private generatePublicKey(modulus: string, exponent: string): Forge.pki.rsa.PublicKey {
        const BigInteger: any = Forge.jsbn.BigInteger;
        const publicKey: Forge.pki.rsa.PublicKey = Forge.pki.rsa.setPublicKey(new BigInteger(modulus, 16), new BigInteger(exponent, 16));
        return publicKey;
    }

    /**
     * 
     * @param modulus Modulus
     * @param exponent Exponent
     * @param message Message
     * @returns hex string
     * @private
     */
    private encrypt(modulus: string, exponent: string, message: string): string {
        const publicKey: Forge.pki.rsa.PublicKey = this.generatePublicKey(modulus, exponent);
        const result: string = Buffer.from(publicKey.encrypt(message, 'RSAES-PKCS1-V1_5'), 'ascii').toString('hex');
        return result;
    }

    /**
     * 
     * @param args: arguments
     * @returns joined string
     * @private
     */
    private joinToString(...args: string[]): string {
        return args.map((e: string) => `${String.fromCharCode(e.length)}${e}`).join('');
    }

    /**
     * 
     * @param rawCookies raw cookies to be converted to JSON object
     * @private
     */
    private parseCookie(rawCookies: string): any {
        const cookies: any = {};
        const rawPair: string[] = rawCookies.split('; ');
        rawPair.forEach((element: string) => {
            const cookiePair: string[] = element.split('=');
            cookies[cookiePair[0]] = cookiePair[1];
        });
        return cookies;
    }

    /**
     * 
     * @param uuid UUIDV4
     * @returns bvsd Object
     * @private
     */
    private bvsdformat(uuid: string): any {
        return {
            a: `${uuid}-4`,
            b: '1.3.4',
            d: [{
                    i: 'id',
                    b: {
                        a: [`0,${this.id}`]
                    },
                    d: `${this.id}`,
                    e: false,
                    f: false
                },
                {
                    i: 'pw',
                    e: true,
                    f: false
                }
            ],
            h: '1f',
            i: {
                a: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
            }
        }
    }

    public async login(): Promise<any> {
        const uuid: string = uuidv4();
        const keys: string = (await Axios.get('https://nid.naver.com/login/ext/keys2.nhn')).data;
        const [
            sessionKey,
            keyname,
            modulus,
            exponent
        ]: string[] = keys.split(',');
        const message: string = this.joinToString(sessionKey, this.id, this.password);
        const encpw: string = this.encrypt(modulus, exponent, message);
        const bvsdcomponent: string = JSON.stringify(this.bvsdformat(uuid));
        const encData: string = LZString.compressToEncodedURIComponent(bvsdcomponent);
        const headers: AxiosRequestConfig = {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
            }
        }
        const data: string = querystring.stringify({
            encpw: encpw,
            enctp: 1,
            svctype: 1,
            smart_LEVEL: -1,
            bvsd: JSON.stringify({
                uuid: uuid,
                encData: encData
            }),
            encnm: keyname,
            locale: 'ko_KR',
            url: 'https://www.naver.com',
            nvlong: 'on'
        });
        let response: AxiosResponse = await Axios.post('https://nid.naver.com/nidlogin.login', data, headers);
        const document: string = response.data;
        const $: cheerio.Root = cheerio.load(document);
        const token: string | undefined = $('input#token_push')?.attr('value');
        if (token) {
            const key: string = $('input#key').attr('value');
            const cookies: string[] = (await Axios.get(`https://nid.naver.com/push/otp?session=${token}`)).headers['set-cookie'];
            const _headers: AxiosRequestConfig = {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
                    'Cookie': cookies.join('; ')
                }
            };
            const _data: string = querystring.stringify({
                mode: 'otp',
                token_push: token,
                key: key,
                auto: '',
                otp: ''
            });
            response = await Axios.post('https://nid.naver.com/nidlogin.login', _data, _headers);
        }
        const cookies: any = {};
        response.headers['set-cookie']?.forEach((element: string) => {
            const cookie: any = this.parseCookie(element);
            for (let key in cookie) {
                if (!['nid_inf', 'NID_AUT', 'NID_SES', 'NID_JKL'].includes(key)) continue;
                cookies[key] = cookie[key];
            }
        });
        if (!('NID_AUT' in cookies)) throw new LoginError('Invalid Id or Password.');
        Object.assign(this.cookies, cookies);
        return new Naver.Response(this);
    }

    static Response = class {
        private naver: Naver;
        /**
         * 
         * @param naver Naver
         * @constructor
         */
        constructor(naver: Naver) {
            this.naver = naver;
        }

        getCookies() {
            return this.naver.cookies;
        }
    }
}

class LoginError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'LoginError';
    }
}

interface NaverCookies {
    nid_inf: string,
    NID_AUT: string,
    NID_SES: string,
    NID_JKL: string
}

export {
    Naver,
    LoginError,
    NaverCookies
}
