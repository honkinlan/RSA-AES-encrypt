import JSEncrypt from 'jsencrypt';
import {KJUR, hextob64, b64tohex} from 'jsrsasign'
// Create the encryption object and set the key.
var cryptor = new JSEncrypt();
// -----BEGIN RSA PRIVATE KEY-----
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDySf3VHbk81ukT
7PL/lNuqVHgFL2muW9mCCF6DqwwfporjstLg36BR/A87bzzferPuMVqCpSpJAXu5
9CuRp5lCB3yANF839CHmslOqwmlFeVoVvnuitdcVh9qvDmn1Ta2G4d47KL7ZVNWa
8RMulWx/ympdMnOJIg493YgMM2YPrW/Rh3+FRr8sqrkimWF+bnlzGoQMcj8nSS+J
KrNLtYIJ4x36o1Ml8SUoz0zuXOoL3O49vnA+tn6ItiPcduV9a6N7hHSOD9fEL4yS
Y84xpVDd8eK6rnUtUpiSANKuxIjPGNk6zkchPL+Lho3iTOz0bZ25hmrGtxg0JyqN
nJUwMWvDAgMBAAECggEAdunTt9YnxPFhYZMozEGd8iIU6c6UWqvfu88pvAumHp6Z
ihmJIC8BO1uviicVREWvq5bzai1v7Hba57Ar9gfA00RjWXTaytZ6EQSyxZs3GY7u
pL9hZMFEd9++d65mWKuwIAQZEwXzbS0SzUHGfVV+89U/kNAjHknlnX1tuTc8vzIW
tnd71zcLaXLzzpJhgkEEGc1IoW7DYfFMuPrhtXk7y+zLIWFbv+7GKDFRJ+e8KTqr
/swEGYshAmD9CRaqW3OGbLb65IOECZTDXFkUuWXSNjfiOYV38nVowq1NIYIQJxIH
JwsToCYfgZQciDvtOh6lZAV8bgG+gwFoPldAM0MfmQKBgQD7Klx2vPwJ1a8UuD7v
EVSPo5kyVr+AfT/CuZ5E1PFcyt7KMT4TsCWjOOSy4VrRHCyRpXwhBjI1uJV4hU4Q
qDIpJIal9F2esOvLdZMa6xQ1UVhn6HpOFj39FT2P8BA1SYaDECcyldr7z+63WsQG
eAZofSjbocbx7iItdODFl34etwKBgQD28+QT5T9YjuhfHtxuneKu6mtXTqJuLXUt
FsziucHZ5byNjSySMv3AdIBAV/Vm/4Ez/AIzamjejou41I4pTOmOE3z+jqFGII7G
pq9P1y1D+v1UUgTliGOvlUKKvkPea6XZpelJGH8MYGkL4Cd2ivQBgVSyfnukYJZP
Mf/ZCB+PVQKBgQCxr7pSVkiIPJ/sLJx5TO1h4P9UWYKJSBJ/lAmf8HYAi5UpvcSI
8SjvXCSPWFaDcUcmkshKJLQIxVkZNlWP+y3hZXHMniBNUCTAf6FefciCH9ZHTHSa
IaohDZHL7q3IxQdgWWEhrFqLowLivFfJq8f8y+7H0p+IMEwFlJYfs5kJ6QKBgQCA
qr4w54bDu2Gy/b9YGwcan6ThzmSvBxxAK9sAXkx0HVDKZ73LRqoTdh/EZo/D5GgL
D8iNxWlyW87MtGKFfj9J+Tls4B+DDD+XnQ1GihRZkRIgtsM6XH+j4h7TbyKpZmj5
J4qOvSak6i6RM28cQnWzuxDIF0KQeIqYJLLq/2KCKQKBgGmxU+ac7trUh3yAuY1t
DoJ1eicKAXCcYIGVs9+Me4WeeyTvZBxeqSYaone0G08JQT9xtCHSRoZPXnb0PL8U
6177XZfdqp6eFDh5kOXsyC9LQjEqYDFgQzRMwWY+yfpL6/o8Ibf5o3dS6me+pvU0
dk9pTm2dDpgZsz5d4tVkCVMp
-----END PRIVATE KEY-----`
// -----END RSA PRIVATE KEY-----

// -----BEGIN PUBLIC KEY-----
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8kn91R25PNbpE+zy/5Tb
qlR4BS9prlvZggheg6sMH6aK47LS4N+gUfwPO28833qz7jFagqUqSQF7ufQrkaeZ
Qgd8gDRfN/Qh5rJTqsJpRXlaFb57orXXFYfarw5p9U2thuHeOyi+2VTVmvETLpVs
f8pqXTJziSIOPd2IDDNmD61v0Yd/hUa/LKq5Iplhfm55cxqEDHI/J0kviSqzS7WC
CeMd+qNTJfElKM9M7lzqC9zuPb5wPrZ+iLYj3HblfWuje4R0jg/XxC+MkmPOMaVQ
3fHiuq51LVKYkgDSrsSIzxjZOs5HITy/i4aN4kzs9G2duYZqxrcYNCcqjZyVMDFr
wwIDAQAB
-----END PUBLIC KEY-----`

// -----END PUBLIC KEY-----

/**
 * 对象转换为key=value并以&连接，并以key名称进行升序排序
 * @param {Object} obj
 * @return {String}
 * **/
function getKeyVal(obj) {
	let str = '';
	const keys = Object.keys(obj).sort();
	for (let key of keys) {
		str += `${key}=${obj[key]}&`
	}
	return str.substr(0, str.length - 1);
}
/**
 * RSA 私钥解密
 * @param {String} str 待解密数据
 * @param {String} privateKey
 * @return {String} 解密后数据
 */
function privateDecrypt(str, privateKey = PRIVATE_KEY) {
	cryptor.setPrivateKey(privateKey);
	return cryptor.decrypt(str)
}
/**
 * RSA 公钥解密
 * @param {String} str 待解密数据
 * @param {String} privateKey
 * @return {String} 解密后数据
 */
function publicDecrypt(str, publicKey = PUBLIC_KEY) {
	cryptor.setPublicKey(publicKey);
	return cryptor.decrypt(str)
}
/**
 * RSA 私钥加密(加签)
 * @param {String} str 待加密数据
 * @param {String} privateKey
 * @return {String} 加密后数据
 */
function privateEncrypt(str, privateKey = PRIVATE_KEY) {
	cryptor.setPrivateKey(privateKey);
	return cryptor.encrypt(str)
}

/**
 * RSA 加密
 * @param {String} str 待加密数据
 * @param {String} publicKey 公钥
 * @return {String} 返回加密字符串
 */
function publicEncrypt(str, publicKey = PUBLIC_KEY) {
	cryptor.setPublicKey(publicKey);
	return cryptor.encrypt(str);
}
/**
 * 使用jsrsasign签名
 * https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html#constructor
 * @param {String} str 需要加密的字符串
 * @return {String} str 签名成功的字符串
 * **/
function signSHA256 (str){
   // RSA signature generation
   let sig = new KJUR.crypto.Signature({alg:"SHA256withRSA"});
   sig.init(PRIVATE_KEY);
   sig.updateString(str);
   return hextob64(sig.sign());
}
/**
 * @param {String} str 未加签的明文
 * @param {String} signStr 待验证的签名
 * @return {Boolean} 签名验证是否成功
 * **/
function signVerify (str, signStr) {
	let sig = new KJUR.crypto.Signature({alg:"SHA256withRSA"});
	sig.init(PUBLIC_KEY);
    sig.updateString(str);
	const isValid = sig.verify(b64tohex(signStr));
	return isValid
}

export default {
	getKeyVal,
	privateDecrypt,
	privateEncrypt,
	publicEncrypt,
	publicDecrypt,
	signSHA256,
	signVerify
}
