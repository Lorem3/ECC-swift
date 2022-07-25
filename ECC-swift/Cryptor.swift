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
            
            
//            {
//                var key1 = [UInt8](repeating: 0, count: keyLen);
//                var nonce = [UInt8](repeating: 0, count: ivLen);
//                memcpy(&key1, key, keyLen);
//                memcpy(&nonce, iv, ivLen);
//                Lprint("aes")
//                Lprint("key",key1.toHexString())
//                Lprint("nonce",nonce.toHexString())
//            }()
          
        case .salsa20:
            var key1 = [UInt8](repeating: 0, count: keyLen);
            var nonce = [UInt8](repeating: 0, count: ivLen);
            memcpy(&key1, key, keyLen);
            memcpy(&nonce, iv, ivLen);
            
            sa = try! Salsa20(key:key1,nonce:nonce)
//
//            Lprint("salsa")
//            Lprint("key",key1.toHexString())
//            Lprint("nonce",nonce.toHexString())
            
            
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
    case scrypt = 1
    case kdfv2 = 2
    case argon2id = 3
}


class KDF{
    let scryptSalt = "The California sea lion (Zalophus californianus) is a coastal species of eared seal native to western North America. It is one of six species of sea lion. Its natural habitat ranges from southeast Alaska to central Mexico, including the Gulf of California. This female sea lion was photographed next to a western gull in Scripps Park in the neighborhood of La Jolla in San Diego, California. [2022-04-07 wikipedia]"
    
    let type:KDFType
    let outLen:Int
    
    var saltArr:[UInt8]
    let saltLen:Int
    var phraseArr:[UInt8]
    deinit{
        saltArr.resetAllBytes()
        phraseArr.resetAllBytes()
    }
    
    init(alg:KDFType,outLen:Int,salt:UnsafeRawPointer,saltLen:Int ,phrase: UnsafeRawPointer,phraseLen:Int){
        type = alg
        self.outLen = outLen
        
        if type == .argon2id {
            saltArr = [UInt8](repeating: 0, count: Int(crypto_pwhash_SALTBYTES))
            self.saltLen = saltArr.count
            memcpy(&saltArr, salt, min(self.saltLen,saltLen))
            
            phraseArr = [UInt8](repeating: 0, count: phraseLen);
            memcpy(&phraseArr, phrase, phraseLen)
            
            
        }else{
            saltArr = [UInt8](repeating: 0, count: saltLen)
            memcpy(&saltArr, salt, saltLen)
            self.saltLen = saltLen
            
            phraseArr = [UInt8](repeating: 0, count: phraseLen);
            memcpy(&phraseArr, phrase, phraseLen)
        }
    }
     
    
    func generateKey(outKey:UnsafeMutableRawPointer,outKeyLen:Int){
        
        
        
        if type == KDFType.kdfv2{
             
            let saltLen = saltArr.count
            let itr = 123456 as UInt32;
            
            phraseArr.withUnsafeBytes { bf  in
                let p = bf.baseAddress?.bindMemory(to: Int8.self, capacity: bf.count);
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),p,phraseArr.count,&saltArr,saltLen,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), itr, outKey.bindMemory(to: UInt8.self, capacity: outKeyLen), outKeyLen)
            }
            
            
            
            
        }else if(type == .scrypt){
            /**
             *  BlockSizeFactor = 8
                ParallelizationFactor = 1
                lgIteration = 14  // 2^14
            */
         
            
            let s = Scrypt();
            s.generatePass(phrase: &phraseArr, phraseSize: phraseArr.count, salt: &saltArr,saltLen:  saltArr.count, derivedKey: outKey, desiredKeyLen: outKeyLen);
        }
        else if(type == .argon2id){
           
            let mem = 8 << 20
            let ops = UInt64(1)
            
            phraseArr.withUnsafeBytes { bf  in
                let p = bf.baseAddress!.bindMemory(to: Int8.self, capacity: bf.count);
                _ = crypto_pwhash_argon2id(outKey.bindMemory(to: UInt8.self, capacity: outKeyLen), UInt64(outKeyLen), p, UInt64(phraseArr.count), &saltArr, ops, mem, crypto_pwhash_alg_argon2id13())
            }
            
        }
    }
}


enum HMACType {
    case sha256;
    case blake2b;
    
    
}
class HMAC{
    var hType:HMACType?
    lazy var ccHmacCtx : CCHmacContext = {
        return CCHmacContext();
    }()
    
    var blake2b_state : OpaquePointer?
    var blake2b_buffer: UnsafeMutableRawPointer?;
    
    let outLen : Int;
    
 
    
    static func     hmac(type:HMACType,key:UnsafePointer<UInt8>,keyLen:Int,msg:UnsafePointer<UInt8> ,msgLen:Int, mac:UnsafeMutablePointer<UInt8>,  macLen:Int){
        let h = HMAC(type: type, key: key , keyLength: keyLen, macLength: macLen)
        h.update(data: msg, size: msgLen)
        h.finish(mac: mac);
        
    }

    
    init(type:HMACType,key:UnsafePointer<UInt8>,keyLength:Int,macLength:Int){
        hType = type
        outLen = macLength;
        if type == HMACType.sha256{
            CCHmacInit(&ccHmacCtx,CCHmacAlgorithm(kCCHmacAlgSHA256),key,keyLength)
            blake2b_state = nil
            
            
        }
        else if(type == .blake2b){
            blake2b_buffer = UnsafeMutableRawPointer.allocate(byteCount: crypto_generichash_blake2b_statebytes(), alignment: 64);
            blake2b_state = OpaquePointer.init(blake2b_buffer!)!
            crypto_generichash_blake2b_init(blake2b_state!, key, keyLength, macLength)
        
            
        }
    }
    
    func update(data:UnsafePointer<UInt8> , size:Int){
        if(hType == .sha256){
            CCHmacUpdate(&ccHmacCtx,data,size)
        }else if(hType == .blake2b){
            crypto_generichash_blake2b_update(blake2b_state!, data, UInt64(size))
        }
    }
    
    func finish(mac:UnsafeMutablePointer<UInt8>  ){
        if(hType == .sha256){
            CCHmacFinal(&ccHmacCtx, mac);
        }else if(hType == .blake2b){
            crypto_generichash_blake2b_final(blake2b_state!, mac, outLen)
        }
    }
    
    deinit{
        if(hType == .sha256){
            
        }else if(hType == .blake2b){
            blake2b_buffer!.deallocate()
        }
    }
}
