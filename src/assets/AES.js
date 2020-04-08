import CryptoJS from 'crypto-js';

/**
 * 转换为字符串
 * @param {*} data 
 * @return {String}
 */
function parseToString(data) {
	var d = '';
	switch (typeof data) {
		case 'string':
			d = data;
			break;
		case 'object':
			d = JSON.stringify(data);
			break;
		default:
			d = data.toString();
	}
	return d;
}
/**
 * 生成指定位数字符
 * @param length
 * @return {String} 返回生成的指定位数字符
 */
function createString(length) {
	var expect = length;
	var str = Math.random().toString(36).substr(2);
	while (str.length < expect) {
		str += Math.random().toString(36).substr(2);
	}
	str = str.substr(0, length);
	return str;
}
/**
 * 生成 AESKEY
 * @return {String} 返回生成的 128位 AESKEY 1byte = 8bits 这里128位实际也是16个字节
 */
function createAesKey() {
	return createString(16);
}

/**
 * 生成 AES 向量iv
 * @return {String} 返回生成的 16位 AES IV
 */
function createAesIv() {
	return createString(16);
}

/**
 * AES 加密
 * mode: CBC (the default)
 * padding: Pkcs7
 * @param data 待加密字段
 * @param aesKey 加密 key
 * @param iv 向量
 * @return {String} 返回加密字段
 */
function encryptAES(data, aesKey, iv) {
	data = CryptoJS.enc.Utf8.parse(parseToString(data));
	// CryptoJS可以从Base64、Latin1或Hex等编码格式转换为WordArray对象，反之亦然
	aesKey = CryptoJS.enc.Base64.parse(aesKey);
	//@bugfixed: iv向量的解析改为Utf8，修复后端解密后乱码的问题...
	iv = CryptoJS.enc.Utf8.parse(iv);
	const encrypted = CryptoJS.AES.encrypt(data, aesKey, {
		iv: iv
	});
	return encrypted.toString();
}

/**
 * AES 解密
 * mode: CBC (the default)
 * @param data 待解密数据
 * @param aesKey 解密 key
 * @param iv 向量
 * @return {String} 返回解密字符串
 */
function decryptAES(data, aesKey, iv) {
	// data = CryptoJS.enc.Utf8.parse(data);
	aesKey = CryptoJS.enc.Base64.parse(aesKey);
	iv = CryptoJS.enc.Utf8.parse(iv);
	var decrypt = CryptoJS.AES.decrypt(data, aesKey, {
		iv: iv
	});
	return CryptoJS.enc.Utf8.stringify(decrypt).toString();
}

export default {
	parseToString,
	createAesIv,
	createAesKey,
	encryptAES,
	decryptAES
}
