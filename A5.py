# -*- coding: utf-8 -*-
# @Time    : 2020-05-09
import re

class A5:
    ''' 
    该类用于进行A5/1流密码的加密和解密。
    A5/1是用于在GSM蜂窝电话标准中提供无线通信隐私的一种加密算法。
    
    类成员：
        origin_key: 一个字符串，用于存储64位初始密钥
        keystream: 一个字符串，用于存储在加/解密时实时生成的密钥流。每次加密/解密均会更新该成员
    '''

    origin_key = ''
    keystream = ''

    def __init__(self, key):
        '''
        构造方法，创建对象时传入初始密钥可进行初始化，支持 int , bytes 和 str 类型。
        当输入 bytes 和 str 类型时，若输入数据长度不为 64 bit则抛出异常；输入 int 类型时则自动将高位补 0 。
        
        参数：
            key: 初始密钥
        '''
        
        if type(key) == str:
            if len(key) != 8:
                raise Exception(
                    "Key length must be 64bit, %dbit given" % (len(key)*8))
            for each in key:
                self.origin_key += bin(ord(each))[2:].zfill(8)
        elif type(key) == int:
            self.origin_key = bin(key)[2:].zfill(64)
        elif type(key) == bytes:
            if len(key) != 8:
                raise Exception("Key length error")
            for each in key:
                self.origin_key += bin(each)[2:].zfill(8)

    def __shift(self, lfsr, num):
        '''
        此方法用于进行三个线性反馈移位寄存器的移位。
        LFSR_1: 第 13, 16, 17, 18 位
        LFSR_2: 第 20, 21 位
        LFSR_3: 第 7, 20, 21, 22 位
        
        参数：
            lfsr: str, 要进行移位的线性反馈移位寄存器
            num: int, 代表线性反馈移位寄存器的编号
        
        返回值：
            str, 移位之后的线性反馈移位寄存器内容
        '''
        
        new_bin = ''
        if num == 1:
            new_bin = str(int(lfsr[13]) ^ int(lfsr[16]) ^ int(lfsr[17]) ^ int(lfsr[18]))
        if num == 2:
            new_bin = str(int(lfsr[20]) ^ int(lfsr[21]))
        if num == 3:
            new_bin = str(int(lfsr[7]) ^ int(lfsr[20]) ^ int(lfsr[21]) ^ int(lfsr[22]))
        
        return new_bin + lfsr[:-1]

    def generate_keystream(self, length):
        '''
        此方法用于生成指定长度的密钥流。
        
        参数：
            length: int, 要求生成密钥流的长度
        
        返回值：
            str, 生成的密钥流
        '''
        
        lfsr_1 = self.origin_key[:19]
        lfsr_2 = self.origin_key[19:41]
        lfsr_3 = self.origin_key[41:]
        keystream_tmp = ''

        print("[*] Generating keystream")
        for i in range(length):
            # 生成密钥流下一位
            keystream_tmp += str(int(lfsr_1[-1]) ^ int(lfsr_2[-1]) ^ int(lfsr_3[-1]))

            # 根据择多原则判断是否需要移位， 参考：https://blog.csdn.net/jerry81333/article/details/78641362
            if int(lfsr_1[8])+int(lfsr_2[10])+int(lfsr_3[10]) >= 2:
                shift_bit = '1'
            else:
                shift_bit = '0'

            if lfsr_1[8] == shift_bit:
                lfsr_1 = self.__shift(lfsr_1, 1)
            elif lfsr_2[10] == shift_bit:
                lfsr_2 = self.__shift(lfsr_2, 2)
            elif lfsr_3[10] == shift_bit:
                lfsr_3 = self.__shift(lfsr_3, 3)
        
        self.keystream = keystream_tmp
        print("[*] Keystream generated")
        return keystream_tmp

    def get_orig_key(self):
        '''
        此方法返回当前对象中的 64bit 原始密钥。
        
        返回值：
            str, 二进制原始密钥字符串
        '''
        
        return self.origin_key

    def encrypt(self, data):
        '''
        此方法用于加密 bytes 和 str 型的数据。
        加密原理是：生成与数据长度等长的密钥流，再和数据进行异或。
        为方便 bytes 和 str 对象的处理，将密钥流按字节分割成了一个 int 数组再逐字节异或。
        
        参数：
            data: 输入的数据
        
        返回值：
            bytes, 被加密后的数据
        '''
        
        print("[*] Start encrypting/decrypting")
        
        tmp_data = []
        if type(data) != str and type(data) != bytes:
            raise TypeError(
                "Input type error, only supports 'str' and 'bytes' object")
        print("[*] Data length %d bytes" % len(data))
        self.generate_keystream(len(data) * 8)   # 按输入数据长度生成密钥流
        
        # 密钥流按字节分割
        key_list = [int('0b'+each, 2)
                    for each in re.findall(r'\w{1,8}', self.keystream)]
        
        if type(data) == bytes:
            for i in range(len(data)):
                tmp_data.append(data[i] ^ key_list[i])
        else:
            for i in range(len(data)):
                tmp_data.append(ord(data[i]) ^ key_list[i])
                
        print("[*] Encrypted/Decrypted")
        return bytes(tmp_data)

    def encrypt_int(self, data):
        '''
        此方法用于加密 int 型的数据。
        
        参数：
            data: int, 输入的数据
        
        返回值：
            int, 加密后的数据
        '''
        
        print("[*] Start encrypting/decrypting")
        if type(data) != int:
            raise TypeError(
                "Input type error, only supports 'int' object")
        self.generate_keystream(len(bin(data)) - 2)
        
        print("[*] Encrypted/Decrypted")
        return data ^ int('0b'+self.keystream, 2)

    def decrypt(self, data, data_type):
        '''
        此方法用于对数据进行解密
        由于加密的过程就是异或，所以进行再次加密即可解密。
        
        参数：
            data: 输入的数据
            data_type: <class 'type'>, 输出数据的类型
        
        返回值：
            解密后的数据
        '''
        
        if data_type != str and data_type != bytes and data_type != int:
            raise TypeError(
                "Input type error, only supports 'str', 'bytes' and 'int' object")
        if data_type == str:
            return self.encrypt(data).decode('utf-8')
        elif data_type == bytes:
            return self.encrypt(data)
        else:
            return self.encrypt_int(data)
