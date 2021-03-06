# 安全存储 - SafeSave

用途：敏感数据加密存储

功能：
1. 加密算法可定制可升级
2. 自带加密数据完整性校验
3. 通过字节映射表转换，实现非标加密算法
4. 加密数据支持不同版本的算法、字节映射表、密钥共存
5. 可动态更新加密数据（无须停机维护，即可增量更换密钥等操作）
6. 密文数据不被彩虹表破解
7. 通过加密云数据，可提取加密算法版本号，加密时间等信息

加密算法1.0版本：
1. 加密固定头部数据，共32字节
2. 前6字节明文保存，分别存储“加密算法主要版本号，次要版本号，字节映射表ID，密钥ID”
3. 末尾8个字节为哈希摘要，用于校验数据完整性
4. 基于AES-128实现数据加密（16字节对齐）
5. 最大支持数据容量为：2GB - 32B
6. 32字节明文的加密解密速度，约为每毫秒20条
7. 密文最短长度为38字节（6字节明文+32字节的密文）
8. 若以二进制存储，数据字段须预留47字节
9. 若以base64存储，数据字段须预留“66字节+明文长度/3”

v1.0数据格式：
1. 1B majorVersion 加密算法主要版本号
2. 1B minorVersion 加密算法次要版本号
3. 1B mappingId 字节映射表ID（从1开始，最大容量255个）
4. 3B keyId 密钥ID（从1开始，最大容量16777215个）
5. 4B reserved 保留字段
6. 6B encryptTime 毫秒时间戳
7. 4B randomCode 随机数
8. 4B plaintextLength 明文数据长度
9. ?B plaintextData 明文数据（可变长度，最少1B，最大2GB）
10. 8B hashCode 数据签名
