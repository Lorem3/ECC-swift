//
//  Cryptor.swift
//  ECC-swift
//
//  Created by wei li on 2022/4/6.
//

import Foundation
import LTScrypt
import AppKit
import CommonCrypto
enum CryptAlgorithm:Int{
    case    aes256 = 0
    case    salsa20 = 1
}
class Cryptor{
    let type:CryptAlgorithm
    var cc:CCCryptorRef?;
    var sa: Salsa20?
    deinit{
        clean();
    }
    init(type: CryptAlgorithm,key:UnsafeRawPointer,keyLen:Int,iv:UnsafeRawPointer,ivLen:Int,encrypt:Bool = true){
        self.type = type;
        switch type {
        case .aes256:
            CCCryptorCreate(CCOperation(encrypt ?kCCEncrypt :kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, kCCKeySizeAES256, iv, &cc);
        case .salsa20:
            var key1 = [UInt8](repeating: 0, count: keyLen);
            var nonce = [UInt8](repeating: 0, count: ivLen);
            memcpy(&key1, key, keyLen);
            memcpy(&nonce, iv, ivLen);
            
            sa = try! Salsa20(key:key1,nonce:nonce)
            memset(&key1 , 0, keyLen);
            memset(&nonce , 0, ivLen);
        }
        
        
    }
    func  crypt(bfIn:UnsafeRawPointer,bfInSize:Int,bfOut:UnsafeMutableRawPointer,bfOutMax:Int,outSize:inout Int){
        
        var outSize0 = 0;
        update(bfIn: bfIn, bfInSize: bfInSize, bfOut: bfOut, bfOutMax: bfOutMax, outSize: &outSize0);
        
        var outSize1 = 0
        final(bfOut: bfOut.advanced(by: outSize0), bfOutMax: bfOutMax - outSize0, outSize: &outSize1);
        outSize = outSize0 + outSize1;
        clean()
    }
    
    
    @inline(__always) func update(bfIn:UnsafeRawPointer,bfInSize:Int,bfOut:UnsafeMutableRawPointer,bfOutMax:Int,outSize:inout Int){
        if type == .aes256{
            CCCryptorUpdate(cc,bfIn,bfInSize,bfOut,bfOutMax,&outSize)
        }
        else if type == .salsa20{
            sa!.update(inData: bfIn, outData: bfOut, size: bfInSize,outSize: &outSize);
        }
        
    }
    
    func clean(){
        if type == .aes256{
            if(cc != nil){
                CCCryptorRelease(cc);
            }
            
        }
        else if type == .salsa20{
            if sa != nil{
                sa!.clean();
            }
        }
        
    }
    
    @inline(__always) func final(bfOut:UnsafeMutableRawPointer,bfOutMax:Int,outSize:inout Int){
        if type == .aes256{
            CCCryptorFinal(cc, bfOut, bfOutMax, &outSize);
            
            cc = nil;
        }
        else if type == .salsa20{
            outSize = 0;
            sa!.final(outData: bfOut, outSize: &outSize);
            sa = nil
        }
    }
    
}


enum KDFType:Int{
    case kdfv2 = 0
    case scrypt = 1
}


class KDF{
    static let scryptSalt = "The California sea lion (Zalophus californianus) is a coastal species of eared seal native to western North America. It is one of six species of sea lion. Its natural habitat ranges from southeast Alaska to central Mexico, including the Gulf of California. This female sea lion was photographed next to a western gull in Scripps Park in the neighborhood of La Jolla in San Diego, California. [2022-04-07 wikipedia]"
    static func generateKey(phrase:UnsafeRawPointer,phraseSize:Int,type:KDFType,outKey:UnsafeMutableRawPointer,outKeyLen:Int){
        
        
        if type == KDFType.kdfv2{
            var salt = [0x2a,0x3d,0xeb,0x93,0xcf,0x9c,0x29,0x81,0xbc,0xb0,0x08,0x57,0x3b,0x98,0x24,0x53,0x99,0xd1,0xac,0x1c,0xee,0x86,0x14,0xbb,0xb6,0xcf,0x79,0xde,0xf7,0x61,0x54,0x71] as [UInt8]
            let saltLen = salt.count;
            let itr = 123456 as UInt32;
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),phrase.bindMemory(to: Int8.self, capacity: phraseSize),phraseSize,&salt,saltLen,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), itr, outKey.bindMemory(to: UInt8.self, capacity: outKeyLen), outKeyLen)
            
        }else {
            /**
             *  BlockSizeFactor = 8
                ParallelizationFactor = 1
                lgIteration = 14  // 2^14
            */
            
            let saltStr = scryptSalt;
            var salt = [UInt8](repeating: 0, count: saltStr.count);
            let saltLen = salt.count;
            saltStr.withCString { bf in
                memcpy(&salt , bf , saltLen);
            }
            
            let s = Scrypt();
            s.generatePass(phrase: phrase, phraseSize: phraseSize, salt: &salt, saltLen: saltLen, derivedKey: outKey, desiredKeyLen: outKeyLen);
        }
    }
}

