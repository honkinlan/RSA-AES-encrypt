<template>
  <div class="hello">
    <h1>{{ msg }}</h1>
    <ul>
      <li>输入需要加密的数据：</li>
      <li class="flex">
        <div class="key">姓名：</div>
        <div class="val">
          <input type="text" v-model="params.name" />
        </div>
      </li>
      <li class="flex">
        <div class="key">身份证：</div>
        <div class="val">
          <input type="text" v-model="params.idcard" />
        </div>
      </li>
      <li class="flex">
        <div class="key">电话：</div>
        <div class="val">
          <input type="text" v-model="params.phone" />
        </div>
      </li>
      <li class="flex">
        <div class="key">其他：</div>
        <div class="val">
          <input type="text" v-model="params.other" />
        </div>
      </li>
    </ul>
    <button @click="encryptData" class="btn">生成加密数据</button>
    <div v-if="encryptedArr.length > 0">
      <ul>
        <li>加密后的数据：</li>
        <li v-for="(item, index) in encryptedArr" :key="index" class="flex">
          <div class="key">{{item.key}}：</div>
          <div class="val">{{item.val}}</div>
        </li>
      </ul>
    </div>
    <button @click="decryptData" class="btn">解密数据</button>
    <div class="text-align padding" v-show="decryptedStatus">
      <span style="color: green;">验证签名成功</span>
    </div>
    <div v-if="decryptedArr.length > 0">
      <ul>
        <li>解密后的数据：</li>
        <li v-for="(item, index) in decryptedArr" :key="index" class="flex">
          <div class="key">{{item.key}}：</div>
          <div class="val">{{item.val}}</div>
        </li>
      </ul>
    </div>
  </div>
</template>

<script>
import Encrypt from "@/assets/encrypt.js";
import Decrypt from "@/assets/decrypt.js";
export default {
  name: "HelloWorld",
  data() {
    return {
      params: {
        name: "username",
        idcard: "511521199912122512",
        phone: "18688888888",
        other: ""
      },
      // 加密后的数据
      encrypted: null,
      encryptedArr: [],
      // 解密后的数据
      decrypted: null,
      decryptedArr: [],
      decryptedStatus: false
    };
  },
  props: {
    msg: String
  },
  methods: {
    // 加密数据 一般放在请求拦截器内
    encryptData() {
      const encryptor = new Encrypt(this.params);
      // data为加密后数据
      let data = encryptor.generateData();
      // ======
      this.encrypted = { ...data };
      this.encryptedArr = this.getKeyValArr(data);
    },
    // 解密数据 一般放在响应拦截器内
    decryptData() {
      const decryptor = new Decrypt(
        this.encrypted.encryptedKey,
        this.encrypted.encryptedData
      );
      // 是否通过签名
      const ispass = decryptor.isPass(
        {
          sequenceNo: this.encrypted.sequenceNo,
          timestamp: this.encrypted.timestamp,
          version: this.encrypted.version
        },
        this.encrypted.signature
      );
      // 如果通过签名
      if (ispass) {
        this.decryptedStatus = ispass;
        // data为解密后的数据
        try {
          let data = JSON.parse(decryptor.decrypted).body;
          this.decryptedArr = this.getKeyValArr(data);
          console.log(data);
        } catch (err) {
          console.log(err);
        }
      }
    },
    /**
     * @param {Object} obj
     * @return {Array} [{key:val}, ...]
     * **/
    getKeyValArr(obj) {
      let arr = [];
      let keys = Object.keys(obj);
      for (let key of keys) {
        arr.push({
          key: key,
          val: obj[key]
        });
      }
      return arr;
    }
  }
};
</script>


<style scoped lang="less">
.text-center {
  text-align: center;
}
.margin {
  margin: 15px;
}
.padding {
  padding: 15px;
}
.btn {
  display: block;
  margin: 20px auto;
  font-size: 16px;
  background: cornflowerblue;
  color: #fff;
  outline: none;
  border: none;
  padding: 4px 10px;
  border-radius: 10px;
}
.flex {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 12px;
  .key {
    font-weight: bold;
    font-size: 14px;
    min-width: 5em;
    text-align: left;
  }
  .val {
    flex:1;
    flex-grow: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: #f00;
    font-size: 12px;
    input{
      width: 100%;
      font-size: 14px;
    }
  }
}
</style>
