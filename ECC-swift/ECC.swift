//
//  ECC.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation
import CommonCrypto
import zlib


private let SECP256K1_FLAGS_TYPE_CONTEXT :UInt32 =  (1 << 0);
private let SECP256K1_FLAGS_BIT_CONTEXT_SIGN : UInt32 = 1 << 9;
private let SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
private let kECPrivateKeyByteCount = 32;
private let SECP256K1_FLAGS_TYPE_COMPRESSION = UInt32(1 << 1);
private let SECP256K1_FLAGS_BIT_COMPRESSION = UInt32(1 << 8)
private let SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)


 


enum LECCError :Error{
    case keyLengthIsNotValid
    case privateKeyIsUnvalid
    case createPublicKeyFail
    case EncryptPubKeyUnvalid
    case EncryptECDHFail
    case DecryptMacNotFit
    case IsNotEnryptByEcc
    case searilizeError
    case inputIsDirectory
    case nilError
}

class LTEccTool {
    /**
     * typeMask 1 zip
     * typeMask 0 notZipd
     **/
    typealias EncryptResult = (ephemPubkeyData:Data,iv:Data,dataEnc:Data,mac:Data,type:UInt16)
    
    @inline(__always) func isZiped(_ type:UInt16) -> Bool{
        return (type & 1) == 0
    }
    @inline(__always) func getCryptAlgrith(_ type:UInt16) -> CryptAlgorithm{
        return (type & 2) == 0 ? .aes256 : .salsa20;
    }
    
    @inline(__always) func getEncType(zip:Bool,alg:CryptAlgorithm) -> UInt16{
        return (zip ? 0 : 1) | (alg == CryptAlgorithm.aes256 ? 0 : 2)
    }
    
    static var shared = LTEccTool();
//    var ctx:OpaquePointer ;
    
    let ec:EC;
    
    init() {
        ec = EC();
    }
    
    func randBuffer(_ s:UnsafeMutableRawPointer ,_ length:Int){
        arc4random_buf(s , length);
    }
    
    func genKeyPair(_ privateKey:String?,keyPhrase:String? ,kdftype:Int = 1) throws ->  (pubKey:String,priKey:String) {
        var _keysNew = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        
        if(privateKey != nil){
            try ec.readSecKey(privateKey!, keyOut: &_keysNew);
        }
        else if keyPhrase != nil {
            let dataKey = keyPhrase?.data(using: .utf8);
            dataKey!.withUnsafeBytes({ bfKey  in
                KDF.generateKey(phrase: bfKey.baseAddress!, phraseSize: bfKey.count, type:kdftype == 1 ? KDFType.scrypt : KDFType.kdfv2, outKey: &_keysNew, outKeyLen: kECPrivateKeyByteCount)
            })
            // compatiable with lower version 
            _keysNew.reverse();
        }
        
        else{
            genSecKey(&_keysNew);
        }
        let strPriKey = ec.serializeSecKeyBytes(&_keysNew)
        var pubkey = ECPubKey()
        try ec.createPubKey(secBytes32: &_keysNew,pubKey: &pubkey)
        defer{
            pubkey.clear()
        }
        let strPubKey = ec.serializePubKey(pubkey);
        return (pubKey:strPubKey,priKey:strPriKey)
        
    }
    
    /// 生成一个合法的私钥
    private func genSecKey(_ secKey32:UnsafeMutableRawPointer){
        ec.generateSecBytes(outBf32: secKey32);
    }
    
    private func genSecKey(_ secKey32:UnsafeMutableRawPointer,phrase:String){
        
    }
    
    
    
    /// 反序列化
    private func deSearilizeToEncResult(_ data:Data)  throws -> EncryptResult{
        
        return try data.withUnsafeBytes { bf -> EncryptResult in
            var Zero = bf.baseAddress?.load(fromByteOffset: 0, as: UInt16.self);
            Zero = CFSwapInt16HostToLittle(Zero!);
            
            var ivLen = bf.baseAddress?.load(fromByteOffset: 2, as: UInt16.self);
            ivLen = CFSwapInt16HostToLittle(ivLen!);
            
            var macLen = bf.baseAddress?.load(fromByteOffset: 4, as: UInt16.self);
            macLen = CFSwapInt16HostToLittle(macLen!);
            
            var ephemPubLen = bf.baseAddress?.load(fromByteOffset: 6, as: UInt16.self);
            ephemPubLen = CFSwapInt16HostToLittle(ephemPubLen!);
            
            guard data.count > Int(macLen!) + Int(ephemPubLen!) + Int(ivLen!) + 8 else {
                throw LECCError.searilizeError
            }
            
            
            var start = 8;
            var end = 8+Int(ivLen!);
            let dataIv = data.subdata(in: start..<end);
            
            start = end;
            end = start + Int(macLen!);
            let dataMac = data.subdata(in: start..<end);
            
            
            start = end;
            end = start + Int(ephemPubLen!);
            let dataEmpher = data.subdata(in: start..<end);
            
            start = end;
            end = data.count;
            let dataEnc = data.subdata(in: start..<end);
            
            return (ephemPubkeyData:dataEmpher,iv:dataIv,dataEnc:dataEnc,mac:dataMac,type:Zero!);
             
        };
        
        
    }
    /// 序列化
    private func searilizeEncResult(_ r:EncryptResult) -> Data{
        var ivLen = UInt16(r.iv.count );
        var macLen = UInt16(r.mac.count)
        var ephemPubLen = UInt16(r.ephemPubkeyData.count) 
        var Zero = r.type as UInt16;
        
        ivLen = CFSwapInt16HostToLittle(ivLen);
        macLen = CFSwapInt16HostToLittle(macLen);
        ephemPubLen = CFSwapInt16HostToLittle(ephemPubLen);
        Zero = CFSwapInt16HostToLittle(Zero);
        
        var dataOut = Data(capacity: r.ephemPubkeyData.count + r.iv.count + r.mac.count + r.dataEnc.count + 8);
        
        withUnsafeBytes(of: &Zero) { bf  in
            dataOut.append(bf.baseAddress!.bindMemory(to: UInt8.self, capacity: 2) , count: 2);
        }
        
        withUnsafeBytes(of: &ivLen) { bf  in
            dataOut.append(bf.baseAddress!.bindMemory(to: UInt8.self, capacity: 2) , count: 2);
        }
        
        withUnsafeBytes(of: &macLen) { bf  in
            dataOut.append(bf.baseAddress!.bindMemory(to: UInt8.self, capacity: 2) , count: 2);
        }
        withUnsafeBytes(of: &ephemPubLen) { bf  in
            dataOut.append(bf.baseAddress!.bindMemory(to: UInt8.self, capacity: 2) , count: 2);
        }
 
         
        dataOut.append(r.iv);
        dataOut.append(r.mac);
        dataOut.append(r.ephemPubkeyData);
        dataOut.append(r.dataEnc);
        
        return dataOut;
        
    }
     
    
    func ecEncrypt(data:Data,pubKey:String ,zipfirst:Int = 1,type:CryptAlgorithm) throws ->Data{
        let pubkey = try! ec.readPubKey(pubKey);
        
        
        var randKey = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        randKey[0] = 2
        // debug
//        genSecKey(&randKey);
        defer {
            randBuffer(&randKey, kECPrivateKeyByteCount);
        }
        
        var randomPub = ECPubKey()
        defer{
            randomPub.clear()
        }
        try! ec.createPubKey(secBytes32: &randKey,pubKey: &randomPub)
        
        var outHash = [UInt8](repeating: 0, count: 64);
        defer {
            outHash.resetBytes(in: 0..<outHash.count)
        }
         
        ec.ecdh(secKeyA: &randKey, pubKeyB: pubkey, outBf64: &outHash);
        
        
        var iv:[UInt8]
        if type == .aes256{
            iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128);
            randBuffer(&iv , kCCBlockSizeAES128);
        }else{
            iv = [UInt8](repeating: 0, count: 24);
            randBuffer(&iv , 24);
        }
        
        
        
        let dataPlain = zipfirst == 1 ? try data.gzipCompress() : data;
        
        let dataOutAvailable = dataPlain.count + kCCBlockSizeAES128
        
        let dataOut = malloc(dataOutAvailable);
        defer{
            free(dataOut);
        }
        
        var outSize = 0;
        dataPlain.withUnsafeBytes { bf  in
            let cy = Cryptor(type: type , key: &outHash, keyLen: 32, iv: &iv, ivLen: iv.count);
            cy.crypt(bfIn: bf.baseAddress!, bfInSize: bf.count, bfOut: dataOut!, bfOutMax: dataOutAvailable, outSize: &outSize)
            cy.clean();
        };
        
       
        
        let dataEnc = Data(bytes: dataOut!, count: outSize)
        let dataIv = Data(bytes: iv, count: iv.count)
        var outPub = [UInt8](repeating: 0, count: ec.pubKeyBufferLength);
        ec.serializePubKey(randomPub, toBytes: &outPub)
        
        let ephemPubkeyData = Data(bytes: outPub, count: ec.pubKeyBufferLength)
        
        var dataForMac = Data(capacity: dataEnc.count + iv.count + ephemPubkeyData.count );
        dataForMac.append(dataIv);
        dataForMac.append(ephemPubkeyData);
        dataForMac.append(dataEnc);
        
        
        var macOut = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH));
        dataForMac.withUnsafeBytes { bf  in
            outHash.withUnsafeBytes { bf2 in
                let pData = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count);
                let outhash32 = bf2.baseAddress?.advanced(by: 32);
                let pHmacKey = UnsafeRawPointer(outhash32);
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),pHmacKey,32,pData,bf.count,&macOut);
            }
            
           
        };
        
        
        let macOutData = Data(bytes: macOut, count: macOut.count);
        
        let t = getEncType(zip: zipfirst == 1, alg: type);
        let result = (ephemPubkeyData:ephemPubkeyData,iv:dataIv,dataEnc:dataEnc,mac:macOutData,type:t);
        
        return searilizeEncResult(result);
        
    }
    
    
    func ecDecrypt(encData:Data,priKey:String) throws -> Data{
     
        let encResult = try deSearilizeToEncResult(encData);
        
        var dataPrivate = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        try! ec.readSecKey(priKey, keyOut: &dataPrivate)
        
        defer {
            memset(&dataPrivate, 0, kECPrivateKeyByteCount)
        }
        
        /// 随机私钥生成的公钥。
        let ephemPubKey = encResult.ephemPubkeyData.withUnsafeBytes { bf  in
            return try! ec.readPubKey(bf.baseAddress!, count: bf.count);
        }
        
        var outHash = [UInt8](repeating: 0, count: 64);
        ec.ecdh(secKeyA: &dataPrivate, pubKeyB: ephemPubKey, outBf64: &outHash)
        
        var dataForMac = Data(capacity: encResult.ephemPubkeyData.count + encResult.iv.count + encResult.dataEnc.count);
        
        dataForMac.append(encResult.iv);
        dataForMac.append(encResult.ephemPubkeyData);
        dataForMac.append(encResult.dataEnc);
        var macOut = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH));
        
        outHash.withUnsafeBytes { bf2 in
            let p = bf2.baseAddress?.advanced(by: 32);
            dataForMac.withUnsafeBytes { bf  in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),p,32,bf.baseAddress,bf.count,&macOut);
            }
        }
         
        if(encResult.mac != Data(macOut)){
            throw LECCError.DecryptMacNotFit
        }
         
        // decrypt
        /// 开始解密
        let  dataOutAvailable : size_t = encResult.dataEnc.count + kCCBlockSizeAES128;
        let dataOut  = malloc(dataOutAvailable);
        defer{
            free(dataOut);
        }
        var outSize : size_t = 0;
        
        _ = encResult.dataEnc.withUnsafeBytes { bfEnc  in
            encResult.iv.withUnsafeBytes { bfIv in
                let t = getCryptAlgrith(encResult.type);
                let cy = Cryptor(type: t, key: outHash, keyLen: 32, iv: bfIv.baseAddress!, ivLen: bfIv.count ,encrypt:false);
                
                cy.crypt(bfIn: bfEnc.baseAddress!, bfInSize: bfEnc.count, bfOut: dataOut!, bfOutMax: dataOutAvailable, outSize: &outSize);
                cy.clean();
            }
        }
        
       

        let dataDec = Data(bytes: dataOut!, count: outSize);
        if isZiped(encResult.type){
            return try dataDec.gzipDecompress()
        }else{
            return dataDec
        }
    }
    
    
    func dealPath(_ path:String) -> String{
        if(path.hasPrefix("/")){
            return String(NSString(string: path).standardizingPath)
        }
        else{
            var cwd = [Int8](repeating: 0, count: Int(PATH_MAX))
            getcwd(&cwd,Int(PATH_MAX))
            
            let strBase = String(cString: cwd);
            return "\(strBase)/\(path)"
        }
    }
    
    
    func ungzipFile(infilePath:String,outfilePath:String ,progress:((Float)->Void)? = nil ){
        let inPath = dealPath(infilePath);
        let outpath = dealPath(outfilePath);
        
        
        let streamOut = OutputStream(toFileAtPath: outpath, append: false)!;
        streamOut.open();
        
        let zipFile = inPath.withCString { bf  in
            return gzopen(bf, "r");
        } as gzFile
        
          
        let maxBuffer = 1 << 20;
        
        let buffer = malloc(maxBuffer).bindMemory(to: UInt8.self, capacity: maxBuffer);
        defer{
            free(buffer)
        }
        
        var uncompressLen = 0 as Int32
        
        repeat{
            uncompressLen = gzread(zipFile, buffer, UInt32(maxBuffer));
            streamOut.write(buffer, maxLength: Int(uncompressLen))
            
            if progress != nil {
                progress!(0.0 as Float)
            }
            
            if uncompressLen == -1 {
                break;
            }
            else if(uncompressLen < maxBuffer){
                break;
            }
                    
        }while true
        
    }
    
    func gzipFile(infilePath:String,outfilePath:String ,progress:((Float)->Void)? = nil ){
        let infile = dealPath(infilePath);
        let outFile = dealPath(outfilePath);
        
        let streamIn = InputStream(fileAtPath: infile)!;
        streamIn.open();
        let outPathBytes = outFile.utf8CString
        var zipFile :gzFile? = nil;
//        gzopen(bf.baseAddress, &"w")
        outPathBytes.withUnsafeBufferPointer { bf  in
            zipFile = gzopen(bf.baseAddress!, "w")
        }
        Lprint(outFile);
        defer{
            gzclose(zipFile);
            streamIn.close();
        }

        let dic1 = try! FileManager.default.attributesOfItem(atPath: infile);
        
        let sizeOfInFile = dic1[FileAttributeKey.size]!
        let fileSize = (sizeOfInFile as! NSNumber).uint64Value;
        var current = 0
        let maxBuffer = 1<<20 as Int
        
        var buffer = [UInt8](repeating: 0, count: maxBuffer);
        var readLen = 0 ;
        var percetn0 = 0 as Float
        
        repeat{
            readLen = streamIn.read(&buffer, maxLength: maxBuffer);
            if (readLen > 0) {
                gzwrite(zipFile, buffer, UInt32(readLen));
                current += readLen;
                if (progress != nil) {
                    let  t = Float(current)/Float(fileSize);
                    if(t - percetn0 > 0.01){
                        percetn0 = t;
                        progress!(t);
                    }
                }
            }
            
        }while (readLen > 0);
    }
    
    func dealOutPath(outpath:String) -> String{
        // check if outpat is exsit, if exsist ,change name by adding _i
        let pathComponets = outpath.split(separator: "/")
        var nameComponet = pathComponets.last!.components(separatedBy: ".")
        let name =  nameComponet.first;
        var fileAutoIndex = 1;
        var result :String = outpath;
        while FileManager.default.fileExists(atPath: result){
            nameComponet[0] = name! + "_\(fileAutoIndex)";
            fileAutoIndex += 1;
            let path = pathComponets.dropLast().joined(separator: "/");
            let name2 = nameComponet.joined(separator: ".");
            result = "/" + path + "/" + name2;
        }
        return result
        
    }
    
    func ecDecryptFile(filePath:String,outFilePath:String?,prikeyString:String ,recursion:Bool = false) throws{
        let inFilePath = dealPath(filePath);
        var outpath:String
        if outFilePath == nil {
            if inFilePath.count > 3 && inFilePath.hasSuffix(".ec") {
                outpath = String(inFilePath[inFilePath.startIndex..<inFilePath.index(inFilePath.endIndex, offsetBy: -3)]);
            }else{
                outpath = inFilePath + ".dec";
            }
        }else{
            outpath = dealPath(outFilePath!);
        }
        
        var isDir = false as ObjCBool
        if(FileManager.default.fileExists(atPath: inFilePath, isDirectory: &isDir)){
            if isDir.boolValue == true {
                if checkDirWorking(dir: inFilePath){
                    return
                }
//                throw LECCError.inputIsDirectory;
                let arr = try! FileManager.default.contentsOfDirectory(atPath: inFilePath)
                setDirFlag(dir: inFilePath, working: true)
                for path  in arr  {
                    do {
                        let sPath = inFilePath + "/\(path)";
                        if sPath.hasSuffix(".ec"){
                            try ecDecryptFile(filePath: sPath, outFilePath: nil , prikeyString: prikeyString, recursion: recursion);
                        }else{
                            FileManager.default.fileExists(atPath: sPath, isDirectory: &isDir)
                            
                            if recursion && isDir.boolValue{
                                print("subDir \(path)")
                                try ecDecryptFile(filePath: sPath, outFilePath: nil , prikeyString: prikeyString, recursion: recursion);
                            }else{
                                print("skip \(path)")
                            }
                        }
                            
                        
                    }
                    catch let e {
                        redPrint(e);
                    }
                }
                
                
                setDirFlag(dir: inFilePath, working: false)
                return;
                
                
            }
        }
        
        outpath = dealOutPath(outpath: outpath);
//
        
        var streamIn = InputStream(fileAtPath: inFilePath)!
        streamIn.open()
        
        let kBfSize = kCCBlockSizeAES128 << 10;
        var readLen  = 0;
        let buffer = malloc(kBfSize).bindMemory(to: UInt8.self, capacity: kBfSize);
        defer{
            free(buffer);
        }
        readLen = streamIn.read(buffer, maxLength: 8);
        
        var type = 0 as UInt16;
        var ivLen = 0 as UInt16;
        var macLen = 0 as UInt16;
        var ephermPubLen = 0 as UInt16;
        
        
        var dataIv : Data?
        var dataMac : Data?
        var dataEphermPubKey : Data?
        var dataStartIndex = 8 + Int(ivLen) + Int(macLen) + Int(ephermPubLen);
        
        if(readLen == 8){
            try buffer.withMemoryRebound(to: UInt16.self, capacity: 4) { bf  in
                type = bf[0].littleEndian
                ivLen = bf[1].littleEndian;
                macLen = bf[2].littleEndian;
                ephermPubLen = bf[3].littleEndian;
                let len1 = Int(ivLen) + Int(macLen) + Int(ephermPubLen);
                
                let len2 = streamIn.read(buffer, maxLength: len1);
                if(len1 != len2){
                    throw LECCError.IsNotEnryptByEcc
                }
                
                dataIv = Data(bytes: buffer, count: Int(ivLen));
                dataMac = Data(bytes: buffer.advanced(by: Int(ivLen) )  , count: Int(macLen));
                dataEphermPubKey = Data(bytes: buffer.advanced(by:Int(ivLen) + Int(macLen)) , count: Int(ephermPubLen));
                
                
                dataStartIndex = 8 + Int(ivLen) + Int(macLen) + Int(ephermPubLen);
                
            };
            
        }else{
            throw LECCError.IsNotEnryptByEcc
        }
        
        var tmpFile :String?
        var streamOut:OutputStream
        let realOutPath = outpath;
        if isZiped(type) {
            tmpFile = outpath + String(format:".%x.gz",arc4random())
            outpath = tmpFile!;
        }
        
        var dhHash = [UInt8](repeating: 64, count: 0)
        
        var privateKey = [UInt8](repeating: 0, count: ec.secKeyBufferLength);
        defer{
            privateKey.resetBytes(in: 0..<privateKey.count)
        }
        try ec.readSecKey(prikeyString, keyOut: &privateKey)
        let pubKey = dataEphermPubKey?.withUnsafeBytes({ bf  in
            return try! ec.readPubKey(bf.baseAddress!, count: bf.count);
        });
        
        ec.ecdh(secKeyA: &privateKey, pubKeyB: pubKey!, outBf64: &dhHash)
        
        /// check mac iv empherpubkey dataenc
        ///
        var  ctx = CCHmacContext();
        dhHash.withUnsafeBytes { bf  in
            CCHmacInit(&ctx,CCHmacAlgorithm(kCCHmacAlgSHA256),bf.baseAddress?.advanced(by: 32),32)
        }
        
        dataIv?.withUnsafeBytes({ bf  in
            CCHmacUpdate(&ctx,bf.baseAddress,bf.count)
        })
        
        dataEphermPubKey?.withUnsafeBytes({ bf  in
            CCHmacUpdate(&ctx,bf.baseAddress,bf.count)
        })
        
        
        let BufferSize =  kCCBlockSizeAES128 << 10
        readLen = streamIn.read(buffer, maxLength: BufferSize);
        
        let dataOutAvailable = BufferSize + kCCBlockSizeAES128
        var dataOut = [UInt8](repeating: 0, count: dataOutAvailable);
        var dataOutLen = 0;
        
        
        let fileSize :Int? = try FileManager.default.attributesOfItem(atPath: inFilePath)[FileAttributeKey.size] as? Int;
        
        let  minDlt =  Int(Double(fileSize!) * 0.01);
        var checked = 0;
        var currentDlt = 0
        
        
        print(inFilePath);
        _printProgress("check", 0);
        while readLen > 0 {
            CCHmacUpdate(&ctx, buffer, readLen);
            readLen = streamIn.read(buffer, maxLength: BufferSize)
            currentDlt += readLen;
            checked += readLen;
            
            if currentDlt >= minDlt {
                currentDlt = 0
                _printProgress("check",  Float(Double(checked)/Double(fileSize!)));
            }
        }
        
        _printProgress("check", 1.0);
        print("");
        
        var macOut = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmacFinal(&ctx, &macOut);
        let macCal = Data(bytes: macOut, count: macOut.count);
        if (macCal != dataMac){
            throw LECCError.DecryptMacNotFit
        }
        
        streamIn.close();
        
        /// decrypt
        streamIn = InputStream(fileAtPath: inFilePath)!;
        streamIn.open();
        streamOut = OutputStream(toFileAtPath: outpath, append: false)!;
        streamOut .open();
        let encryptDataSize = fileSize! - dataStartIndex
        let minShowProgressSize = Int(Double(encryptDataSize) * 0.01);
        
        
        streamIn.setProperty(dataStartIndex, forKey: Stream.PropertyKey.fileCurrentOffsetKey)
        
        let alg = getCryptAlgrith(type);
        var cryptor_ : Cryptor?;
        
        dataIv!.withUnsafeBytes({ bf  in
            cryptor_ = Cryptor(type: alg, key: dhHash, keyLen: 32, iv: bf.baseAddress!, ivLen: bf.count,encrypt: false)
        })
        
        let cryptor = cryptor_!
        
        readLen = streamIn.read(buffer, maxLength: BufferSize);
        var currentDecrypt = 0
        var currentDelt = 0
        while readLen > 0{
            
            cryptor.update(bfIn: buffer, bfInSize: readLen, bfOut: &dataOut, bfOutMax: dataOutAvailable, outSize: &dataOutLen)
            
            if dataOutLen > 0 {
                streamOut.write(&dataOut, maxLength: dataOutLen);
                currentDecrypt += dataOutLen;
                currentDelt += dataOutLen;
                if (currentDelt >= minShowProgressSize) {
                    currentDelt = 0;
                    _printProgress("decrypt", Float(currentDecrypt)/Float(encryptDataSize))
                    
                }
            }
            readLen = streamIn.read(buffer, maxLength: BufferSize);
            
        }
        cryptor.final(bfOut: &dataOut, bfOutMax: dataOutAvailable, outSize: &dataOutLen)
        
        if dataOutLen > 0 {
            streamOut.write(&dataOut, maxLength: dataOutLen);
            
        }
        _printProgress("decrypt",1.0)
        print("")
        
        if tmpFile != nil && isZiped(type) {
            print("unzipping, please wait...");
            fflush(stdout)
            ungzipFile(infilePath: tmpFile!, outfilePath: realOutPath)
            print("\rUnzipping Done                                 " );
        }
        
        
        streamIn.close();
        streamOut.close();
        if(tmpFile != nil && isZiped(type)){
            let  fzip  = tmpFile?.withCString({ bf  in
                 return  fopen(bf, "r+");
            })
            fseek(fzip,0,SEEK_END)
            let sz = ftell(fzip);
            fseek(fzip,0,SEEK_SET)
            
            var c = 0;
            var rnd = [UInt8](repeating: 0, count: 16);
            repeat{
                randBuffer(&rnd, rnd.count);
                fwrite(&rnd, rnd.count, 1, fzip)
                c += rnd.count
            }while c < 1024 && c < sz
            fclose(fzip);
            try? FileManager.default.removeItem(atPath: tmpFile!);
        }
        
        print("output",realOutPath)
        
    }
    static var rnd = SystemRandomNumberGenerator();
    static var dirFlag = ".\(rnd.next())"
    func setDirFlag(dir:String, working:Bool){
        let flagFile = dir + "/" + LTEccTool.dirFlag;
        if working{
            FileManager.default.createFile(atPath: flagFile, contents: nil , attributes: nil )
        }else{
            try? FileManager.default.removeItem(atPath: flagFile)
        }
    }
    
    func checkDirWorking(dir:String) -> Bool{
        let flagFile = dir + "/" + LTEccTool.dirFlag;
        return FileManager.default.fileExists(atPath: flagFile)
    }
    
    func ecEncryptFile(filePath:String,outFilePath:String?,pubkeyString:String,gzip:(Bool) = true ,alg:CryptAlgorithm,recursion :Bool = false) throws{
        var inFilePath = dealPath(filePath);
        
        var isDir = false as ObjCBool;
        if(FileManager.default.fileExists(atPath: inFilePath, isDirectory: &isDir)){
            if isDir.boolValue == true  {
                if checkDirWorking(dir: inFilePath){
                   return
                }
                let arr = try! FileManager.default.contentsOfDirectory(atPath: inFilePath)
                setDirFlag(dir: inFilePath, working: true)
                for path  in arr  {
                    do {
                        let sPath = inFilePath + "/\(path)";
                        
                        FileManager.default.fileExists(atPath: sPath, isDirectory: &isDir)
                        
                        if  isDir.boolValue{
                            if recursion {
                                print("subDir \(path)")
                                try ecEncryptFile(filePath:sPath,outFilePath:nil, pubkeyString:pubkeyString , gzip:gzip,alg:alg,recursion:recursion);
                            }else{
                                print("subDir skip ...",path)
                            }
                        }
                        else{
                            if sPath.hasSuffix(".ec")
                                || sPath.hasSuffix(".DS_Store")
                                || sPath.hasSuffix(LTEccTool.dirFlag){
                                print("skip",sPath)
                            }else{
                                try ecEncryptFile(filePath:sPath,outFilePath:nil, pubkeyString:pubkeyString , gzip:gzip,alg:alg,recursion:false);
                            }
                            
                        }
                        
                        
                    }
                    catch let e {
                        redPrint(e);
                    }
                }
                setDirFlag(dir: inFilePath, working: false)
                return;
            }
        }
        
        let originInFile = inFilePath;
        var strziptmp:String?;
        if gzip == true {
            let components = inFilePath.split(separator: "/")
            let directory = components.dropLast(1).map(String.init).joined(separator: "/")
            strziptmp = "/" + directory + String(format: "/%x.ectmp",arc4random()  );
            
            print("");

            gzipFile(infilePath: inFilePath, outfilePath: strziptmp!) { p in
                self._printProgress("zipping", p);
            };
            self._printProgress("zipping", 1);
            print("");
            inFilePath = strziptmp!;
        }
        
        var outPath: String
        if outFilePath != nil {
            outPath = dealPath(outFilePath!);
        }
        else{
            outPath = originInFile + ".ec"
        }
        outPath = dealOutPath(outpath: outPath);
        
        let _streamIn  = InputStream(fileAtPath: inFilePath);
        let _streamOut  = OutputStream(toFileAtPath:outPath , append: false);
        
        guard _streamIn != nil  ,_streamOut != nil else {
            return;
        }
        
        let streamIn = _streamIn!
        let streamOut = _streamOut!
        streamIn.open();
        streamOut.open();
        
        
        /// generate
        var dhHash = [UInt8](repeating: 0, count: 64);
        defer{
            dhHash.resetBytes(in: 0..<dhHash.count)
        }
        var publen = ec.pubKeyBufferLength;
        var outPub = [UInt8](repeating: 0, count: publen);
        var pubkey = try ec.readPubKey(pubkeyString)
       
        var randKey = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        genSecKey(&randKey);
        defer{
            randBuffer(&randKey, kECPrivateKeyByteCount);
            genSecKey(&randKey);
        }
        var randomPub = ECPubKey()
        try! ec.createPubKey(secBytes32: &randKey,pubKey: &randomPub);
        defer{
            randomPub.clear()
        }
        
        ec.ecdh(secKeyA: &randKey, pubKeyB: pubkey, outBf64: &dhHash);
        ec.serializePubKey(randomPub, toBytes: &outPub)
        
        var macPostion = 0
        var macBuffer = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        var iv:[UInt8]
        if alg == .salsa20{
            iv = [UInt8](repeating: 0, count: Int(24))
            randBuffer(&iv , iv.count)
        }else{
            iv = [UInt8](repeating: 0, count: Int(kCCBlockSizeAES128))
            randBuffer(&iv , iv.count)
        }
        
        
        
        var ivLen = UInt16(iv.count)
        var macLen = UInt16(CC_SHA256_DIGEST_LENGTH)
        var ephemPubLen = UInt16(publen);
        var Zero = getEncType(zip: gzip, alg: alg)
         
        ivLen = CFSwapInt16HostToLittle(ivLen);
        macLen = CFSwapInt16HostToLittle(macLen);
        ephemPubLen = CFSwapInt16HostToLittle(ephemPubLen);
        
        withUnsafeBytes(of: &Zero) { bf  in
            let p = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count)
            streamOut.write(p, maxLength: bf.count);
        }
        withUnsafeBytes(of: &ivLen) { bf  in
            let p = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count)
            streamOut.write(p, maxLength: bf.count);
        }
        
        withUnsafeBytes(of: &macLen) { bf  in
            let p = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count)
            streamOut.write(p, maxLength: bf.count);
        }
        
        withUnsafeBytes(of: &ephemPubLen) { bf  in
            let p = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count)
            streamOut.write(p, maxLength: bf.count);
        }
        
        streamOut.write(&iv , maxLength: Int(ivLen))
        streamOut.write(&macBuffer , maxLength: Int(macLen))
        streamOut.write(&outPub , maxLength: Int(ephemPubLen))
        
        /// we need update real hmac value after it's done, now it's all zero
        macPostion = 8 + Int(ivLen);
        
        var cryptor:Cryptor
        cryptor = Cryptor(type: alg, key: &dhHash, keyLen: 32, iv: &iv, ivLen: iv.count);
         
        var ctx:CCHmacContext = CCHmacContext();
        
        defer {
            cryptor.clean();
            self.randBuffer(&dhHash, dhHash.count);
        }
        
        dhHash.withUnsafeBufferPointer { bf  in
            CCHmacInit(&ctx, CCHmacAlgorithm(kCCHmacAlgSHA256) , bf.baseAddress?.advanced(by: 32), 32);
        }
        CCHmacUpdate(&ctx,&iv,iv.count)
        CCHmacUpdate(&ctx,&outPub,publen);
        
        var readDateLen = 0;
        
        let buffersize = kCCBlockSizeAES128 << 10;
        let encbuffersize = buffersize + kCCBlockSizeAES128;
        
        
        let buffer = malloc(buffersize).bindMemory(to: UInt8.self, capacity: buffersize)
        let bufferEncry = malloc(encbuffersize).bindMemory(to: UInt8.self, capacity: encbuffersize);
        defer {
            memset(buffer, 0, buffersize);
            free(buffer);
            free(bufferEncry);
        }
        
        readDateLen = streamIn .read(buffer, maxLength: buffersize);
        var encsize = 0;
  
        
        let zipfilesize = try? (FileManager.default.attributesOfItem(atPath: inFilePath)[FileAttributeKey.size] as! Int);
        let minDeltSize = Int(Double(zipfilesize!) * 0.01)
        
        print("");
        var encryptedSize = 0;
        var encryptedDelt = 0;
        while readDateLen > 0{
            cryptor.update(bfIn: buffer, bfInSize: readDateLen, bfOut: bufferEncry, bfOutMax: encbuffersize, outSize: &encsize);
            
            
            // calculate hmac
            if encsize > 0 {
                CCHmacUpdate(&ctx, bufferEncry, encsize);
                streamOut .write(bufferEncry, maxLength: encsize);
                encryptedDelt += encsize;
                encryptedSize += encsize;
                
                if encryptedDelt > minDeltSize{
                    encryptedDelt = 0;
                    _printProgress("encrypt", Float(Double(encryptedSize)/Double(zipfilesize!) as Double))
                }
            }
            
            readDateLen = streamIn.read(buffer ,maxLength:buffersize);
        }
        cryptor.final(bfOut: bufferEncry, bfOutMax: encbuffersize, outSize: &encsize);
        CCHmacUpdate(&ctx,bufferEncry,encsize);
        CCHmacFinal(&ctx, &macBuffer);
        
        if encsize > 0 {
            streamOut.write(bufferEncry, maxLength: encsize);
        }
        
        _printProgress("encrypt",1.0)
        print("");
        
        streamIn.close();
        streamOut.close();
        
        
        /// update mac of  Header
        var fileOut : UnsafeMutablePointer<FILE>?
        if outPath.count > 0 {
            outPath.utf8CString.withUnsafeBufferPointer { bf  in
                fileOut = fopen(bf.baseAddress, "r+b");
            };
        }
        fseeko(fileOut!, off_t(macPostion), SEEK_SET);
        fwrite(macBuffer, Int(macLen), 1, fileOut!);
        fclose(fileOut!)
        
        /// remove zip file
        if gzip == true && strziptmp != nil {
            let  fzip  = strziptmp?.withCString({ bf  in
                 return  fopen(bf, "r+");
            })
            fseek(fzip,0,SEEK_END)
            let sz = ftell(fzip);
            fseek(fzip,0,SEEK_SET)
            
            var c = 0;
            repeat{
                randBuffer(&macBuffer, macBuffer.count);
                fwrite(&macBuffer, macBuffer.count, 1, fzip)
                c += macBuffer.count
            }while c < 1024 && c < sz
            fclose(fzip);
            try? FileManager.default.removeItem(atPath: strziptmp!);
        }
        
        print("out:",outPath);
         
    }
    
    
    private  func _printProgress(_ msg:String,_ percent0:Float ){
        let percent = percent0 > 1 ? 1 : percent0;
         
        print("\r" + msg + " ", separator: "", terminator: "");
         
        let  max = 35;
        let  progres = Int((percent * Float(max)))
        
        for _ in 0..<min(progres,max) {
            print("█", separator: "", terminator: "");
        }
        
        
        let  left = max - progres;
        for _ in 0..<left{
            print("░", separator: "", terminator: "");
        }
         
        print(" \(String(format: "%.1f", 100.0 * percent))%", separator: "", terminator: "");
        fflush(stdout)
    }
    
 

}

extension FileHandle : TextOutputStream {
  public func write(_ string: String) {
    guard let data = string.data(using: .utf8) else { return }
    self.write(data)
  }
}

func Lprint(_ msg:Any ... ,file:String = #file,name:String = #function, line :Int = #line){
    
    var stderr = FileHandle.standardError
    print("\(name) line:\(line) :" ,to:&stderr);
    
    
    for i in msg{
        print(i , separator:"", terminator: " ",to:&stderr);
    }
    print("",to:&stderr);
    
}




