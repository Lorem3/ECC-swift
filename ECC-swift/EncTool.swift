//
//  ECC.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation
import CommonCrypto
import zlib
import CryptoKit
enum ECCZipTyp {
    case gzip;
    case nogzip;
    case auto;
    
}

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
    case FileLost
    case IsNotEnryptByEcc
    case searilizeError
    case inputIsDirectory
    case nilError
    case encDataError
}

class EncTool {
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
    
    @inline(__always)  static  func getCurveType(_ type:UInt16) -> CurveType{
        return (type & 4) == 0 ? .Secp256k1 : .Curve25519;
    }
    
    @inline(__always) func getEncType(zip:Bool,alg:CryptAlgorithm) -> UInt16{
        return  (curveType == .Secp256k1 ? 0 : 4)  |  ((zip ? 0 : 1) | (alg == CryptAlgorithm.aes256 ? 0 : 2))
    }
    
    static var Secp255k1 : EncTool  = {
        return EncTool(CurveType.Secp256k1)
    }()
    
    static var Curve25519 : EncTool  = {
        return EncTool(CurveType.Curve25519)
    }()
    
//    var ctx:OpaquePointer ;
    
    let ec:ECFun;
    let curveType:CurveType
    
    let chunkSize = kCCBlockSizeAES128 << 15;// kCCBlockSizeAES128 << 10;
    init(_ curve:CurveType) {
        
        if curve == .Secp256k1{
            curveType = curve
            ec = EC()
        }else if(curve == .Curve25519){
            curveType = curve
            ec = EC_X25519();
        }else{
            curveType = .Curve25519
            ec = EC_X25519();
        }
    }
    
    func randBuffer(_ s:UnsafeMutableRawPointer ,_ length:Int){
        arc4random_buf(s , length);
    }
    
    func genKeyPair(_ privateKey:String?) throws ->  (pubKey:String,priKey:String) {
        var _keysNew = [UInt8](repeating: 0, count: ec.secLen);
        
        if(privateKey != nil){
            try ec.readSecKey(privateKey!, seckey: &_keysNew);
        }
        else{
            genSecKey(&_keysNew);
        }
        let strPriKey = try ec.seckeyToString(&_keysNew)
        var pub = [UInt8](repeating: 0, count: ec.pubLen);
        
        ec.genPubKey(seckey: &_keysNew, pubkey: &pub)
        let strPubKey = try ec.pubkeyToString(&pub);
        return (pubKey:strPubKey,priKey:strPriKey)
        
    }
    
    /// 生成一个合法的私钥
    private func genSecKey(_ secKey32:UnsafeMutableRawPointer){
        ec.generateSecBytes(secKey32);
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
    static func ecEncrypt(data:Data,pubKey:String ,zipfirst:Int = 1,type:CryptAlgorithm) throws ->Data{
        return try Curve25519.ecEncrypt(data: data, pubKey: pubKey, zipfirst:zipfirst, type: type);
    }
    
    func ecEncrypt(data:Data,pubKey:String ,zipfirst:Int = 1,type:CryptAlgorithm) throws ->Data{
        var pubKeyEnc = [UInt8](repeating: 0, count: ec.pubLen)
        try ec.readPubKey(pubKey, pubkey: &pubKeyEnc)
        
        var randKey = [UInt8](repeating: 0, count: ec.secLen);
        var randPub = [UInt8](repeating: 0, count: ec.pubLen);
        try ec.genKeyPair(seckey: &randKey, pubkey: &randPub)
        var outHash = [UInt8](repeating: 0, count: 64);
        defer {
            pubKeyEnc.resetAllBytes()
            randKey.resetAllBytes()
            randPub.resetAllBytes()
            outHash.resetAllBytes()
        }
        
        try ec.ecdh(secKeyA: &randKey, pubKeyB: &pubKeyEnc, outBf64: &outHash,sharePoint: nil)
      
         
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
 
        let ephemPubkeyData = Data(bytes: randPub, count: ec.pubLen)
        
        var dataForMac = Data(capacity: dataEnc.count + iv.count + ephemPubkeyData.count );
        dataForMac.append(dataIv);
        dataForMac.append(ephemPubkeyData);
        dataForMac.append(dataEnc);
        
        
        var macOut = [UInt8](repeating: 0, count:32);
        dataForMac.withUnsafeBytes { bf  in
            outHash.withUnsafeBytes { bf2 in
                let pData = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count);
                let outhash32 = bf2.baseAddress!.advanced(by: 32);
                let pHmacKey = outhash32.bindMemory(to: UInt8.self, capacity: 32);
                
                let ht = curveType == .Curve25519 ? HMACType.blake2b : .sha256
                
                HMAC.hmac(type: ht, key: pHmacKey, keyLen: 32, msg: pData, msgLen: bf.count, mac: &macOut, macLen: macOut.count)
             }
        };
        
        
        let macOutData = Data(bytes: macOut, count: macOut.count);
        
        let t = getEncType(zip: zipfirst == 1, alg: type);
        let result = (ephemPubkeyData:ephemPubkeyData,iv:dataIv,dataEnc:dataEnc,mac:macOutData,type:t);
        
        return searilizeEncResult(result);
        
    }
    
    static func ecDecrypt(encData:Data,priKey:String) throws -> Data{
        if encData.count > 10{
            
            let curve = encData.withUnsafeBytes { bf  -> CurveType in
            var Zero = bf.baseAddress!.load(fromByteOffset: 0, as: UInt16.self);
             Zero = CFSwapInt16HostToLittle(Zero);
             return getCurveType(Zero)
            }
            
            if curve == .Curve25519{
                return try Curve25519.ecDecrypt(encData: encData, priKey: priKey)
            }else{
                return try Secp255k1.ecDecrypt(encData: encData, priKey: priKey)
            }
           
            
        }else{
            throw LECCError.encDataError
        }
        
    }
    
    func ecDecrypt(encData:Data,priKey:String) throws -> Data{
     
        let encResult = try deSearilizeToEncResult(encData);
        
        var dataPrivate = [UInt8](repeating: 0, count: ec.secLen);
        /// 随机私钥生成的公钥。
        var ephemPubKey = [UInt8](repeating: 0, count: ec.pubLen);
        
        try! ec.readSecKey(priKey, seckey: &dataPrivate)
        
        defer {
            dataPrivate.resetAllBytes()
            ephemPubKey.resetAllBytes()
        }
        
        
        _ = try encResult.ephemPubkeyData.withUnsafeBytes { bf in

            try ec.convertPubKeyCanonical(pub: bf.baseAddress!, pubSize: bf.count, toPub: &ephemPubKey)
        }
        
        var outHash = [UInt8](repeating: 0, count: 64);
        try ec.ecdh(secKeyA: &dataPrivate, pubKeyB: &ephemPubKey, outBf64: &outHash,sharePoint: nil)
    
        var dataForMac = Data(capacity: encResult.ephemPubkeyData.count + encResult.iv.count + encResult.dataEnc.count);
        
        dataForMac.append(encResult.iv);
        dataForMac.append(encResult.ephemPubkeyData);
        dataForMac.append(encResult.dataEnc);
        var macOut = [UInt8](repeating: 0, count:32 );
        
        outHash.withUnsafeBytes { bf2 in
            let p = bf2.baseAddress?.advanced(by: 32).bindMemory(to: UInt8.self, capacity: 32);
            dataForMac.withUnsafeBytes { bf  in
//                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),p,32,bf.baseAddress,bf.count,&macOut);
                let ht = curveType == .Curve25519 ? HMACType.blake2b : .sha256

                HMAC.hmac(type: ht, key: p!, keyLen: 32, msg: bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count), msgLen: bf.count, mac: &macOut, macLen: macOut.count)

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
                var t = getCryptAlgrith(encResult.type);
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
        return EncTool.dealPath(path)
    }
    static func dealPath(_ path:String) -> String{
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
        return EncTool.dealOutPath(outpath: outpath)
    }
    
    
    func checkIsPartial(_ path:String) -> Bool{
        return path.contains(".ecpart_")
    }
    // a.ec a.ecpart_1.ec  ->  a.ecpart_1.ec a.ecpart_2.3c
    func setPartIndx(_ path:String,idx:Int) -> String{
        
        let _ptname = "ecpart_\(String(idx, radix: 10, uppercase: false))"
        let ptname = _ptname[_ptname.startIndex..<_ptname.endIndex]
        
        var arr = path.split(separator: "/",omittingEmptySubsequences:false)
        let name = arr.last;
        var arrName = name!.split(separator: ".")
        
        assert(arrName.count >= 2, "path error:\(path)")
        let nameComponet = arrName[arrName.count - 2]
        if nameComponet.hasPrefix("ecpart_"){
            arrName[arrName.count - 2] = ptname
        }else{
            arrName.insert(ptname, at: arrName.count - 1)
        }
        
        
        let newName = arrName.joined(separator: ".");
        arr[arr.count - 1] = newName[newName.startIndex..<newName.endIndex]
        
        
        return arr.joined(separator: "/")
         
    }
    static func dealOutPath(outpath:String ,isDec:Bool = false) -> String{
        // check if outpat is exsit, if exsist ,change name by adding _i
        let pathComponets = outpath.split(separator: "/")
        var nameComponet = pathComponets.last!.components(separatedBy: ".")
        if isDec && outpath.contains(".ecpart_") {
            nameComponet = nameComponet.dropLast()
        }
        let name =  nameComponet.first;
        var fileAutoIndex = 1;
        var result :String = "/" + pathComponets.dropLast().joined(separator: "/") + "/" + nameComponet.joined(separator: ".")
        while FileManager.default.fileExists(atPath: result){
            nameComponet[0] = name! + "_\(fileAutoIndex)";
            fileAutoIndex += 1;
            let path : String
            path = pathComponets.dropLast().joined(separator: "/");
            let name2 = nameComponet.joined(separator: ".");
            result = "/" + path + "/" + name2;
        }
        return result
        
    }
    

    static func filterDirFilesWhenDecrypt(_ fileName:String) -> Bool{
        if fileName.hasSuffix(".ec"){
            if fileName.contains(".ecpart_") && !fileName.contains(
                ".ecpart_1.") {
                return false
            }
            return true
        }
        return false
    }
   
    static func ecDecryptFile(filePath:String,outFilePath:String?,prikeyString:String ,recursion:Bool = false) throws{
        var inFilePath = dealPath(filePath);
        let isPartialFile = Curve25519.checkIsPartial(inFilePath)
        var partralCount = 0
        if isPartialFile {
            inFilePath = EncTool.Curve25519.setPartIndx(inFilePath, idx: 1)
        }
        
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
                        if filterDirFilesWhenDecrypt(sPath){
                            Lprint(sPath)
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
        
        
        outpath = dealOutPath(outpath: outpath,isDec: true);
//
        
        var streamIn = InputStream(fileAtPath: inFilePath)!
        streamIn.open()
        
        let kBfSize = Curve25519.chunkSize
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
        
        let ectool = getCurveType(type) == .Curve25519 ? Curve25519 : Secp255k1;
        
        var tmpFile :String?
        var streamOut:OutputStream
        let realOutPath = outpath;
        if ectool.isZiped(type) {
            tmpFile = outpath + String(format:".%x.gz",arc4random())
            outpath = tmpFile!;
        }
        
        var dhHash = [UInt8](repeating: 0, count: 64)
        
        var privateKey = [UInt8](repeating: 0, count: ectool.ec.secLen);
        var pubKey = [UInt8](repeating: 0, count: ectool.ec.pubLen);
        defer{
            privateKey.resetAllBytes()
            pubKey.resetAllBytes()
        }
        try ectool.ec.readSecKey(prikeyString, seckey: &privateKey)
        
        try dataEphermPubKey?.withUnsafeBytes({ bf  in
            try ectool.ec.convertPubKeyCanonical(pub: bf.baseAddress!, pubSize: bf.count, toPub: &pubKey)
            
        });
        
        try ectool.ec.ecdh(secKeyA: &privateKey, pubKeyB: &pubKey, outBf64: &dhHash,sharePoint: nil)
        
        /// check mac iv empherpubkey dataenc
        
        let hmactype : HMACType = ectool.curveType == .Curve25519 ? .blake2b : .sha256
        
        let hmac = dhHash.withUnsafeBytes { bf  in
            return HMAC(type: hmactype, key: bf.baseAddress!.advanced(by: 32).bindMemory(to: UInt8.self, capacity: 32), keyLength: 32, macLength: 32)
        }
        
        dataIv?.withUnsafeBytes({ bf  in
            hmac.update(data: bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count), size: bf.count)
        })
        
        dataEphermPubKey?.withUnsafeBytes({ bf  in
            hmac.update(data: bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count), size: bf.count)
        })
        
        
        let BufferSize = Curve25519.chunkSize// kCCBlockSizeAES128 << 10
        
        
        if isPartialFile{
            var fileCountBf = [UInt8](repeating: 0, count: 4);
            dataIv?.withUnsafeBytes({ bf0  in
                dataMac?.withUnsafeBytes({ bf1 in
                    for i in 0..<4{
                        fileCountBf[i] = bf0.load(fromByteOffset: i, as: UInt8.self) ^ bf1.load(fromByteOffset: i, as: UInt8.self)
                    }
                })
            })
            
            
            
            
            let tmp  = fileCountBf.withUnsafeBytes({ bf  in
                return bf.load(as: UInt32.self)
            })
            partralCount = Int(CFSwapInt32LittleToHost(tmp))
            
        }
        
        
        
        let dataOutAvailable = BufferSize + kCCBlockSizeAES128
        var dataOut = [UInt8](repeating: 0, count: dataOutAvailable);
        var dataOutLen = 0;
        
        
  
        print(inFilePath);
        print("check...")
        
        var filePart = 1;
        
        repeat {
            readLen = streamIn.read(buffer, maxLength: BufferSize);
            if readLen > 0 {
                hmac.update(data: buffer, size: readLen)
            }
            
            if isPartialFile && readLen <= 0 && filePart < partralCount{
                streamIn.close()
                filePart += 1
                inFilePath = Curve25519.setPartIndx(inFilePath, idx: filePart)
                let s = InputStream(fileAtPath: inFilePath);
                if s == nil {
                    throw LECCError.FileLost
                }
                streamIn = s!
                streamIn.open();
                
                readLen = 1
                continue
            }
            
        }while readLen > 0
        
        print("check done.");
        if isPartialFile && filePart != partralCount{
            throw LECCError.FileLost
        }
        
        
        var macOut = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        hmac.finish(mac:&macOut )
        
        if macOut.count !=  dataMac!.count {
            throw LECCError.DecryptMacNotFit
        }
         
        try dataMac?.withUnsafeBytes({ bf  in
            if isPartialFile{
                
                try macOut.withUnsafeBytes { bfmac  in
                    let z = memcmp(bf.baseAddress!.advanced(by: 4),
                                   bfmac.baseAddress!.advanced(by: 4), macOut.count - 4)
                    if 0 != z {
                        throw LECCError.DecryptMacNotFit
                    }
                }
                
            }else{
                if 0 != memcmp(bf.baseAddress, &macOut, macOut.count){
                    throw LECCError.DecryptMacNotFit
                }
            }
        })
        
        
        streamIn.close();
        
        
        if isPartialFile{
            inFilePath = Curve25519.setPartIndx(inFilePath, idx: 1)
        }
            
        
        /// decrypt
        streamIn = InputStream(fileAtPath: inFilePath)!;
        streamIn.open();
        streamOut = OutputStream(toFileAtPath: outpath, append: false)!;
        streamOut .open();
        
        print("decrypt...")
  
        streamIn.setProperty(dataStartIndex, forKey: Stream.PropertyKey.fileCurrentOffsetKey)
        
        let alg = ectool.getCryptAlgrith(type);
        var cryptor_ : Cryptor?;
        
        dataIv!.withUnsafeBytes({ bf  in
            cryptor_ = Cryptor(type: alg, key: dhHash, keyLen: 32, iv: bf.baseAddress!, ivLen: bf.count,encrypt: false)
        })
        
        let cryptor = cryptor_!
        
        
        var currentDecrypt = 0
        var currentDelt = 0
        
        var fileIdx = 1;
        
       repeat{
            readLen = streamIn.read(buffer, maxLength: BufferSize);
            cryptor.update(bfIn: buffer, bfInSize: readLen, bfOut: &dataOut, bfOutMax: dataOutAvailable, outSize: &dataOutLen)
            
            if dataOutLen > 0 {
                streamOut.write(&dataOut, maxLength: dataOutLen);
                currentDecrypt += dataOutLen;
                currentDelt += dataOutLen;
                
            }
            
            if readLen <= 0 && isPartialFile && fileIdx < partralCount {
                streamIn.close()
                fileIdx += 1
                inFilePath = Curve25519.setPartIndx(inFilePath, idx: fileIdx)
                streamIn = InputStream(fileAtPath: inFilePath)!
                streamIn.open()
                
                readLen = 1
            }
            
        }while readLen > 0
        cryptor.final(bfOut: &dataOut, bfOutMax: dataOutAvailable, outSize: &dataOutLen)
        
        if dataOutLen > 0 {
            streamOut.write(&dataOut, maxLength: dataOutLen);
            
        }
        print("decrypt done")
        
        
        if tmpFile != nil && ectool.isZiped(type) {
            print("unzipping, please wait...");
            fflush(stdout)
            ectool.ungzipFile(infilePath: tmpFile!, outfilePath: realOutPath)
            print("\rUnzipping Done                                 " );
        }
        
        
        streamIn.close();
        streamOut.close();
        if(tmpFile != nil && ectool.isZiped(type)){
            let  fzip  = tmpFile?.withCString({ bf  in
                 return  fopen(bf, "r+");
            })
            fseek(fzip,0,SEEK_END)
            let sz = ftell(fzip);
            fseek(fzip,0,SEEK_SET)
            
            var c = 0;
            var rnd = [UInt8](repeating: 0, count: 16);
            repeat{
                ectool.randBuffer(&rnd, rnd.count);
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
    static func setDirFlag(dir:String, working:Bool){
        let flagFile = dir + "/" + EncTool.dirFlag;
        if working{
            FileManager.default.createFile(atPath: flagFile, contents: nil , attributes: nil )
        }else{
            try? FileManager.default.removeItem(atPath: flagFile)
        }
    }
    func setDirFlag(dir:String, working:Bool){
        EncTool.setDirFlag(dir: dir, working: working)
    }
    func checkDirWorking(dir:String) -> Bool{
        return EncTool.checkDirWorking(dir: dir)
    }
    static func checkDirWorking(dir:String) -> Bool{
        let flagFile = dir + "/" + EncTool.dirFlag;
        return FileManager.default.fileExists(atPath: flagFile)
    }
    
    func ecEncryptFile(filePath:String,outFilePath:String?,pubkeyString:String,zipType:ECCZipTyp ,alg:CryptAlgorithm,recursion :Bool = false,fileLengthMB:Int = -1) throws{
        var inFilePath = dealPath(filePath);

        let gzip : Bool
        switch zipType {
        case .gzip:
            gzip = true
        case .nogzip:
            gzip = false
        case .auto:
            gzip = fileLengthMB > 0 ? false : true
        }
        
        
        
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
                                try ecEncryptFile(filePath:sPath,outFilePath:nil, pubkeyString:pubkeyString , zipType:zipType ,alg:alg,recursion:recursion,fileLengthMB:fileLengthMB);
                            }else{
                                print("subDir skip ...",path)
                            }
                        }
                        else{
                            if sPath.hasSuffix(".ec")
                                || sPath.hasSuffix(".DS_Store")
                                || sPath.hasSuffix(EncTool.dirFlag){
                                print("skip",sPath)
                            }else{
                                try ecEncryptFile(filePath:sPath,outFilePath:nil, pubkeyString:pubkeyString , zipType:zipType,alg:alg,recursion:false,fileLengthMB:fileLengthMB);
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
            
            print("zipping...");

            gzipFile(infilePath: inFilePath, outfilePath: strziptmp!)
            print("zipping done");
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
        
        
        var partIdx = 1
        let isPatrial : Bool;
        if fileLengthMB > 0  {
            outPath = setPartIndx(outPath, idx: partIdx);
            isPatrial = true
        }else{
            isPatrial = false
        }
        
        
        let _streamIn  = InputStream(fileAtPath: inFilePath);
        let _streamOut  = OutputStream(toFileAtPath:outPath , append: false);
        
        guard _streamIn != nil  ,_streamOut != nil else {
            return;
        }
        
        let streamIn = _streamIn!
        var streamOut = _streamOut!
        streamIn.open();
        streamOut.open();
        
        var fileLen = fileLengthMB > 0 ? (Int64(fileLengthMB) << 20) : Int64(0)
        let isPartialFile = fileLen > 0
        
        /// generate
        var dhHash = [UInt8](repeating: 0, count: 64);
        defer{
            dhHash.resetAllBytes()
        }
        
        
        var pubKeyEnc = [UInt8](repeating: 0, count: ec.pubLen);
        var randKey = [UInt8](repeating: 0, count: ec.secLen);
        var randPub = [UInt8](repeating: 0, count: ec.pubLen);
        try! ec.genKeyPair(seckey: &randKey, pubkey: &randPub);
        defer{
            randPub.resetAllBytes()
            randKey.resetAllBytes()
            pubKeyEnc.resetAllBytes()
        }
          
        try ec.readPubKey(pubkeyString, pubkey: &pubKeyEnc)
        try ec.ecdh(secKeyA: &randKey, pubKeyB: &pubKeyEnc, outBf64: &dhHash,sharePoint: nil);
        
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
        var ephemPubLen = UInt16(ec.pubLen);
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
        streamOut.write(&randPub , maxLength: Int(ephemPubLen))
        
        /// we need update real hmac value after it's done, now it's all zero
        macPostion = 8 + Int(ivLen);
        
        var cryptor:Cryptor
        cryptor = Cryptor(type: alg, key: &dhHash, keyLen: 32, iv: &iv, ivLen: iv.count);
         
        
        let hmactype : HMACType = curveType == .Curve25519 ? .blake2b : .sha256

        
        defer {
            cryptor.clean();
            self.randBuffer(&dhHash, dhHash.count);
        }
        
        let hmac = dhHash.withUnsafeBytes { bf  in
            return HMAC(type: hmactype, key: bf.baseAddress!.advanced(by: 32).bindMemory(to: UInt8.self, capacity: 32), keyLength: 32, macLength: 32)
        }
        hmac.update(data: &iv , size: iv.count)
        hmac.update(data: &randPub , size: ec.pubLen)
        
        var readDateLen = 0;
        
        let buffersize = chunkSize ;//kCCBlockSizeAES128 << 10;
        let encbuffersize = buffersize + kCCBlockSizeAES128;
        
        
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: buffersize, alignment: 16);
      
        let bufferEncry = UnsafeMutableRawPointer.allocate(byteCount: encbuffersize, alignment: 16);
        
        let pBufferEncry = bufferEncry.bindMemory(to: UInt8.self, capacity: encbuffersize)
        let pBuffer = buffer.bindMemory(to: UInt8.self, capacity: buffersize)
        
        defer {
            sodium_memzero(pBuffer, buffersize)
            bufferEncry.deallocate()
            buffer.deallocate()
        }
        
        print("encrypt...");
        var encsize = 0;
        var filePartSize = Int64(8 + Int(ivLen) + Int(macLen) + Int(ephemPubLen))
        
  
        repeat{
            readDateLen = streamIn.read(pBuffer ,maxLength:buffersize);
            if readDateLen > 0 {
                cryptor.update(bfIn: buffer, bfInSize: readDateLen, bfOut: bufferEncry, bfOutMax: encbuffersize, outSize: &encsize);
                
                // calculate hmac
                if encsize > 0 {
                    hmac.update(data: pBufferEncry, size: encsize)
                     
                    if isPatrial && filePartSize + Int64(encsize) > fileLen {
                        
                        let left = fileLen - filePartSize
                        if left > 0 {
                            streamOut.write(pBufferEncry, maxLength: Int(left));
                            streamOut.close()
                            partIdx += 1
                            outPath = setPartIndx(outPath, idx: partIdx);
                            streamOut = OutputStream(toFileAtPath:outPath , append: false)!;
                            streamOut.open()
                            
                            filePartSize = filePartSize + Int64(encsize) - fileLen;
                            streamOut.write(pBufferEncry.advanced(by: Int(left)), maxLength: Int(filePartSize));
                            
                            
                            
                            
                            
                            continue
                        }
                        else{
                            streamOut.close()
                            partIdx += 1
                            outPath = setPartIndx(outPath, idx: partIdx);
                            streamOut = OutputStream(toFileAtPath:outPath , append: false)!;
                            streamOut.open()
                            filePartSize = 0;
                        }
                        
                    }
     
                    streamOut.write(pBufferEncry, maxLength: encsize);
                    
                    filePartSize += Int64(encsize)
                    
                    
                }
            }
             
        }while readDateLen > 0
        
        cryptor.final(bfOut: pBufferEncry, bfOutMax: encbuffersize, outSize: &encsize);
        
        hmac.update(data: pBufferEncry, size: encsize)
        hmac.finish(mac: &macBuffer)
        
        
        /// macBuffer
        
        /***
         *
         *  分卷模式，mac 最开始的4字节作为 分卷数量。
         *
         **/
        if isPartialFile{
            let count = UInt32(partIdx).littleEndian
            
            macBuffer[0] = iv[0] ^ UInt8((count & (0xff << 0)) >> 0)
            macBuffer[1] = iv[1] ^ UInt8((count & (0xff << 8)) >> 8)
            macBuffer[2] = iv[2] ^ UInt8((count & (0xff << 16)) >> 16)
            macBuffer[3] = iv[3] ^ UInt8((count & (0xff << 24)) >> 24)
            
            
        }
        
        
        if encsize > 0 {
            streamOut.write(pBufferEncry, maxLength: encsize);
        }
        
        print("encrypt done.");
        
        streamIn.close();
        streamOut.close();
        
        
        /// update mac of  Header
        var fileOut : UnsafeMutablePointer<FILE>?
        if outPath.count > 0 {
            
            if isPartialFile {
                let fisrtFile = setPartIndx(outPath, idx: 1)
                fisrtFile.utf8CString.withUnsafeBufferPointer { bf  in
                    fileOut = fopen(bf.baseAddress, "r+b");
                };
            }else{
                outPath.utf8CString.withUnsafeBufferPointer { bf  in
                    fileOut = fopen(bf.baseAddress, "r+b");
                };
            }
           
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
        return
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




