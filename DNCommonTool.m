/*
 //
 //  DNHTTPProxyManager.h
 //  HTTPAgent
 //
 //  Created by 王缘 on 16/11/16.
 //  Copyright © 2016年 . All rights reserved.
 //  Company .
 
 */
#import "DNCommonTool.h"
#import <Commoncrypto/CommonDigest.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <objc/runtime.h>
#import "Reachability.h"


@implementation DNCommonTool
//对象转字典
+ (NSDictionary*)getObjectData:(id)obj
{
    NSMutableDictionary *dic = [NSMutableDictionary dictionary];
    unsigned int propsCount;
    objc_property_t *props = class_copyPropertyList([obj class], &propsCount);//获得属性列表
    for(int i = 0;i < propsCount; i++)
    {
        objc_property_t prop = props[i];
        
        NSString *propName = [NSString stringWithUTF8String:property_getName(prop)];//获得属性的名称
        id value = [obj valueForKey:propName];//kvc读值
        if(value == nil)
        {
            value = [NSNull null];
        }
        else
        {
            value = [self getObjectInternal:value];//自定义处理数组，字典，其他类
            [dic setObject:value forKey:propName];
        }
    }
    return dic;
}

+ (id)getObjectInternal:(id)obj
{
    if([obj isKindOfClass:[NSString class]]
       || [obj isKindOfClass:[NSNumber class]]
       || [obj isKindOfClass:[NSNull class]])
    {
        return obj;
    }
    
    if([obj isKindOfClass:[NSArray class]])
    {
        NSArray *objarr = obj;
        NSMutableArray *arr = [NSMutableArray arrayWithCapacity:objarr.count];
        for(int i = 0;i < objarr.count; i++)
        {
            [arr setObject:[self getObjectInternal:[objarr objectAtIndex:i]] atIndexedSubscript:i];
        }
        return arr;
    }
    
    if([obj isKindOfClass:[NSDictionary class]])
    {
        NSDictionary *objdic = obj;
        NSMutableDictionary *dic = [NSMutableDictionary dictionaryWithCapacity:[objdic count]];
        for(NSString *key in objdic.allKeys)
        {
            [dic setObject:[self getObjectInternal:[objdic objectForKey:key]] forKey:key];
        }
        return dic;
    }
    return [self getObjectData:obj];
}

//MD5加密
+ (NSString *)md5:(NSString *)input {
    
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(cStr,(CC_LONG)strlen(cStr), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        
        [output appendFormat:@"%02X",digest[i]];
    }
    
    return output;
}

//SHA512加密
+ (NSString *)sha512:(NSString *)input {
    
    const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:input.length];
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data.bytes, (unsigned int)data.length, digest);
    NSMutableString* output = [NSMutableString  stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
     
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}


/**
 ** 动态key生成算法
 ** 将请求参数按照 JSON 格式进行 Base64 转码
 **/
+ (NSString *)createKeyWithParamDict:(NSDictionary *)dict {
    
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:nil];
    
    return [data base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

/**
 ** sign签名生成算法
    将所有请求参数按照参数名升序排序, 排序后，按请求参数名及参数值相互连接组成字符串，并在前面加入DNION成为新的字符串s
    token签名sign: Sign=MD5(SHA512(s)+secretKey)
    其他签名sign:   Sign=MD5(SHA512(s)+token)

 **/
+ (NSString *)createSignWithParamDict:(NSDictionary *)dict SecretKey:(NSString *)key {
    
    //先将字典key升序存在数组，再进行遍历取出value
    NSArray *keys = [dict allKeys];
    NSArray *sortedArray = [keys sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2){
        return [obj1 compare:obj2 options:NSNumericSearch];
    }];
    
    //拼接字符串
    NSMutableString *mStr = [NSMutableString string];
    //第一步 添加头标记 DNION
    [mStr appendString:DNIONKEY];
    
    //第二步 按升序拼接各参数名和参数值
    for (NSString *categoryId in sortedArray) {
    
        [mStr appendFormat:@"%@%@", categoryId, [dict objectForKey:categoryId]];
    }
    
    DNLog(@"mstr :%@", mStr);
    //第三步 将字符串进行sha512编码
    NSString *sha512 = [DNCommonTool sha512:mStr];
    
    //第四步 将编码后的字符串与密钥拼接
    NSMutableString *sign = [NSMutableString stringWithString:sha512];
    [sign appendFormat:@"%@", key];
    
    return [DNCommonTool md5:sign];
}


// 是否WIFI
+ (BOOL)isEnableWIFI {
    return ([[Reachability reachabilityWithHostName:@"www.baidu.com"] currentReachabilityStatus] == ReachableViaWiFi);
}

// 是否3G
+ (BOOL)isEnable3G {
    return ([[Reachability reachabilityForInternetConnection] currentReachabilityStatus] == ReachableViaWWAN);
}

/**
 *  MNC
 中国移动: 00 02 07
 中国联通: 01 06
 中国电信: 03 05 11
 返回运营商名称
 */
+ (DNCarrierName)getCarrierName{
    
    CTTelephonyNetworkInfo *info = [[CTTelephonyNetworkInfo alloc]init];
    
    CTCarrier *carrier = [info subscriberCellularProvider];
    
    NSString *countryCode = [carrier mobileCountryCode];
    NSString *networkCode = [carrier mobileNetworkCode];
    
    //中国地区码
    if ([countryCode isEqualToString:@"460"]) {
        
        
        if ([networkCode isEqualToString:@"00"] ||
            [networkCode isEqualToString:@"02"] ||
            [networkCode isEqualToString:@"07"]) {
            // 中国移动: 00 02 07
            return DNChinaMobile;
            
        }else if ([networkCode isEqualToString:@"01"] ||
                  [networkCode isEqualToString:@"06"] ) {
            
            // 中国联通:  01 06
            return DNChinaUnicom;
            
        }else if ([networkCode isEqualToString:@"03"] ||
                  [networkCode isEqualToString:@"05"] ||
                  [networkCode isEqualToString:@"11"]) {
            
            // 中国电信: 03 05 11
            return DNChinaTelecom;
        }
    }
    return DNCarrierNameNone;
}

//判断手机号码是否合法
+ (BOOL)isMobileNumber:(NSString *)mobileNum {
    
    //    电信号段:133/153/180/181/189/173/177
    //    联通号段:130/131/132/155/156/185/186/145/176
    //    移动号段:134/135/136/137/138/139/150/151/152/157/158/159/182/183/184/187/188/147/178
    //    虚拟运营商:170
    
    NSString *MOBILE = @"^1(3[0-9]|4[57]|5[0-35-9]|8[0-9]|7[036-8])\\d{8}$";
    
    NSPredicate *regextestmobile = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", MOBILE];
    
    return [regextestmobile evaluateWithObject:mobileNum];
}

//二进制转16进制
+ (NSString*)byteToString:(NSData*)data {
    
    Byte *plainTextByte = (Byte *)[data bytes];
    NSString *hexStr=@"";
    for(int i=0;i<[data length];i++)
    {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",plainTextByte[i]&0xff];///16进制数
        if([newHexStr length]==1)
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        else
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
    }
    return hexStr;
}

//生成16位随机向量
+ (NSString *)randstringWithLength:(NSUInteger)length {
    
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    
    if (result == 0) {
        
        return [[DNCommonTool byteToString:data] substringToIndex:length];
    }else
        
        return nil;
}

//获取当前时间戳 单位ms
+ (NSString *)currentTimeStampString {
    
    NSTimeInterval interval =  [[NSDate date] timeIntervalSince1970]*1000;
    return [NSString stringWithFormat:@"%ld", (long)interval];
}

//AES-CFB-256加密
+ (NSData *)AES256Operation:(CCOperation)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES256 + 1]; //32位KEY
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    char ivPtr[kCCBlockSizeAES128 + 1]; //16位向量
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
    }
    free(buffer);
    return nil;
}

+ (NSData *)AES256EncryptWithData:(NSData *)data Key:(NSString *)key iv:(NSString *)iv
{
    return [DNCommonTool AES256Operation:kCCEncrypt data:data key:key iv:iv];
}

+ (NSData *)AES256DecryptWithData: (NSData *)data Key:(NSString *)key iv:(NSString *)iv
{
    return [DNCommonTool AES256Operation:kCCDecrypt data:data key:key iv:iv];
}

//3DES 加密
+ (NSString *)TripleDESEncryptWithplainText:(NSString*)plainText key:(NSString *)key iv:(NSString *)iv {
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    plainTextBufferSize = [data length];
    vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *)[key UTF8String];
    const void *ivPrt = (const void *)[iv UTF8String];
    
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding ,//kCCOptionECBMode
                       vkey,
                       kCCKeySize3DES,
                       ivPrt,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    if (ccStatus == kCCSuccess) {
        NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
        NSString *result = [myData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
        
        return result;
    }
    
    free(bufferPtr);
    return nil;
}

@end
