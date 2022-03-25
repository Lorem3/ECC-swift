//
//  ECC.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation


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
    case nilError
}

class LTEccTool {
    typealias EncryptResult = (ephemPubkeyData:Data,iv:Data,dataEnc:Data,mac:Data,type:UInt16)
    
    
    static var shared = LTEccTool();
    var ctx:OpaquePointer ;
    
    init() {
        let  blocksize : size_t = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN)
        
        let p = malloc(blocksize)
        self.ctx = secp256k1_context_preallocated_create(p!,SECP256K1_CONTEXT_SIGN);
        var buf:[UInt8] = Array<UInt8>.init(repeating: 0, count: 32);
        randBuffer(&buf,  32);
        _ = secp256k1_context_randomize(ctx,&buf);
    }
    
    func randBuffer(_ s:UnsafeMutableRawPointer ,_ length:Int){
        arc4random_buf(s , length);
    }
    
    func genKeyPair(_ privateKey:String?,keyPhrase:String?) throws ->  (pubKey:String,priKey:String) {
        var dataPrivate : Data?;
        
        var _keysNew = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        
        if(privateKey != nil){
            dataPrivate = try LTBase64.base64Decode(privateKey!);
            if dataPrivate?.count != kECPrivateKeyByteCount {
                throw LECCError.keyLengthIsNotValid
            }
            
            try dataPrivate?.withUnsafeBytes(){ (bf:UnsafeRawBufferPointer) in
                let p0 = bf.baseAddress;
                let p2 = p0?.bindMemory(to: UInt8.self, capacity: bf.count);
                if(secp256k1_ec_seckey_verify(self.ctx, p2!) == 0 ){
                    throw LECCError.privateKeyIsUnvalid
                }
                memcpy(&_keysNew, p2, kECPrivateKeyByteCount);
            };
        }
        else if keyPhrase != nil {
            var salt = [0x2a,0x3d,0xeb,0x93,0xcf,0x9c,0x29,0x81,0xbc,0xb0,0x08,0x57,0x3b,0x98,0x24,0x53,0x99,0xd1,0xac,0x1c,0xee,0x86,0x14,0xbb,0xb6,0xcf,0x79,0xde,0xf7,0x61,0x54,0x71] as [UInt8]
            let saltLen = salt.count;
            let itr = 123456;
            
        
            let kk = keyPhrase?.data(using: .utf8);
            repeat{
                _ = kk!.withUnsafeBytes({ bf in
                    let p = bf.baseAddress?.bindMemory(to: Int8.self, capacity: bf.count)
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),p,bf.count,&salt,saltLen,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(itr), &_keysNew , kECPrivateKeyByteCount)
                })
            }while secp256k1_ec_seckey_verify(self.ctx , &_keysNew) == 0
            
             
        }
        
        else{
            genSecKey(&_keysNew);
        }
        
        
        var pubkey : secp256k1_pubkey = secp256k1_pubkey();
        let r = secp256k1_ec_pubkey_create(self.ctx, &pubkey,&_keysNew);
        if r == 0{
            throw LECCError.createPublicKeyFail
        }
        
        var pPubOut65 = [UInt8](repeating: 0, count: 65);
        var  pubLen = 65 as size_t;
        
        secp256k1_ec_pubkey_serialize(self.ctx,&pPubOut65,&pubLen, &pubkey,UInt32(SECP256K1_EC_COMPRESSED));
        
        
        let strPubKey = Data(bytes: &pPubOut65, count: pubLen).base64EncodedString()
        
        let strPriKey = Data(bytes: &_keysNew, count:kECPrivateKeyByteCount ).base64EncodedString();
        
        return (pubKey:strPubKey,priKey:strPriKey)
        
    }
    
    /// 生成一个合法的私钥
    private func genSecKey(_ secKey32:UnsafeMutableRawPointer){
        var tmp:[UInt8] = [UInt8](repeating: 0 , count: 64);
        var tmpdata:[UInt8] = [UInt8](repeating: 0 , count: 128);
        
        let p = UnsafePointer<UInt8>(OpaquePointer(secKey32));
        repeat{
            randBuffer(&tmp,64);
            randBuffer(&tmpdata,128);
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),tmp ,64,tmpdata,128,secKey32);
        }while (0 == secp256k1_ec_seckey_verify(self.ctx , p))
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
    
    
    private  let my_ecdh_hash_function :  secp256k1_ecdh_hash_function =  {
        (output: UnsafeMutablePointer<UInt8>?, x32:UnsafePointer<UInt8>?  ,y32:UnsafePointer<UInt8>? ,data:UnsafeMutableRawPointer?) -> CInt in
        CC_SHA512(x32, 32, output);
        return 1;
    }
    
    
    
    
    func ecEncrypt(data:Data,pubKey:String ,zipfirst:Int = 1) throws ->Data{
        var pubkey = secp256k1_pubkey();
        var _dataPub:Data;
        do{
            _dataPub = try LTBase64.base64Decode(pubKey);
        }
        catch let e {
            throw e;
        }
        
        let dataPub = _dataPub;
        
        try _dataPub.withUnsafeBytes({ bf in
            let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count)
            
            let r = secp256k1_ec_pubkey_parse(self.ctx,&pubkey, p!,dataPub.count)
            if r == 0{
                throw LECCError.EncryptPubKeyUnvalid
            }
        });
        
        
       
        
        var randKey = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        genSecKey(&randKey);
        defer {
            randBuffer(&randKey, kECPrivateKeyByteCount);
        }
        
         
        
        var randomPub = secp256k1_pubkey();
        var r2 = secp256k1_ec_pubkey_create(self.ctx, &randomPub, &randKey)
        if (r2 == 0){
            throw LECCError.createPublicKeyFail
        }
        
        var outHash = [UInt8](repeating: 0, count: 64);
         
        r2 = secp256k1_ecdh(self.ctx,&outHash,&pubkey,randKey,my_ecdh_hash_function,nil)
        if(r2 == 0){
            throw LECCError.EncryptECDHFail
        }
        
        
        var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128);
        randBuffer(&iv , kCCBlockSizeAES128);
        
        let dataPlain = zipfirst == 1 ? try data.gzipCompress() : data;
        
        let dataOutAvailable = dataPlain.count + kCCBlockSizeAES128
        
        let dataOut = malloc(dataOutAvailable);
        defer{
            free(dataOut);
        }
        
        var outSize = 0;
        
        _ = dataPlain.withUnsafeBytes { bf  in
            CCCrypt(CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),      /* kCCOptionPKCS7Padding, etc. */
                    outHash,
                    kCCKeySizeAES256,
                    iv,
                    bf.baseAddress,
                    bf.count,
                    dataOut,
                    dataOutAvailable,
                    &outSize);
        };
        
       
        
        let dataEnc = Data(bytes: dataOut!, count: outSize)
        let dataIv = Data(bytes: iv, count: iv.count)
        var outPub = [UInt8](repeating: 0, count: 65);
        var len = 65;
        
        secp256k1_ec_pubkey_serialize(self.ctx, &outPub, &len,&randomPub, UInt32(SECP256K1_EC_COMPRESSED));
        
        let ephemPubkeyData = Data(bytes: outPub, count: len)
        
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
        let result = (ephemPubkeyData:ephemPubkeyData,iv:dataIv,dataEnc:dataEnc,mac:macOutData,type:UInt16(zipfirst == 1 ? 0 : 1));
        
         
        return searilizeEncResult(result);
        
    }
    
    
    func ecDecrypt(encData:Data,priKey:String) throws -> Data{
     
        let encResult = try deSearilizeToEncResult(encData);
        let dataPrivate0 = try LTBase64.base64Decode(priKey);
        if dataPrivate0.count != kECPrivateKeyByteCount{
            throw LECCError.privateKeyIsUnvalid;
        }
        
        
        var datePrivate = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        for i in 0..<kECPrivateKeyByteCount{
            datePrivate[i] = dataPrivate0[i];
        }
        
        /// 随机私钥生成的公钥。
        var ephemPubKey = secp256k1_pubkey();
        try encResult.ephemPubkeyData.withUnsafeBytes { bf in
            let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count);
            let r = secp256k1_ec_pubkey_parse(self.ctx, &ephemPubKey, p!, bf.count);
            if r == 0{
                throw LECCError.EncryptPubKeyUnvalid
            }
        }
        
        var outHash = [UInt8](repeating: 0, count: 64);
        
        let r0 = secp256k1_ecdh(self.ctx, &outHash, &ephemPubKey, &datePrivate, my_ecdh_hash_function, nil);
        if(r0 == 0){
            throw LECCError.EncryptECDHFail;
        }
        
        
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
                CCCrypt(CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        outHash,
                        kCCKeySizeAES256,
                        bfIv.baseAddress,
                        bfEnc.baseAddress,
                        bfEnc.count,
                        dataOut,
                        dataOutAvailable,
                        &outSize);
                
            }
        }
        
       

        let dataDec = Data(bytes: dataOut!, count: outSize);
        if encResult.type == 0{
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
    
    func ecDecryptFile(filePath:String,outFilePath:String?,prikeyString:String) throws{
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
        
        outpath = dealOutPath(outpath: outpath);
//
        
        var streamIn = InputStream(fileAtPath: inFilePath)!
        streamIn.open()
        
        let kCCBlockSizeAES128 = kCCBlockSizeAES128 << 10;
        var readLen  = 0;
        let buffer = malloc(kCCBlockSizeAES128).bindMemory(to: UInt8.self, capacity: kCCBlockSizeAES128);
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
                Lprint(type,ivLen,macLen,ephermPubLen);
                
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
        if type == 0 {
            tmpFile = outpath + String(format:".%x.gz",arc4random())
            outpath = tmpFile!;
        }
        
        var dhHash = [UInt8](repeating: 64, count: 0)
        let dataPrikey = try LTBase64.base64Decode(prikeyString);
        try dataPrikey.withUnsafeBytes { bf in
            if 0 == secp256k1_ec_seckey_verify(self.ctx, bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count)){
                throw LECCError.privateKeyIsUnvalid
            }
        }
        var ephemPubKey = secp256k1_pubkey()
        try dataEphermPubKey?.withUnsafeBytes({ bf  in
            let r0 = secp256k1_ec_pubkey_parse(self.ctx,&ephemPubKey,(bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count))!,bf.count);
            if r0 == 0 {
                throw LECCError.EncryptPubKeyUnvalid
            }
        })
        
        try dataPrikey.withUnsafeBytes { bf in
            let r_ecdh = secp256k1_ecdh(self.ctx, &dhHash, &ephemPubKey, bf.baseAddress!.bindMemory(to: UInt8.self, capacity: bf.count), my_ecdh_hash_function, nil);
            
            if r_ecdh == 0 {
                throw LECCError.EncryptECDHFail
            }
        }
        
        
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
        var dataOut = [UInt8](repeating: 0, count: BufferSize);
        var dataOutLen = 0;
        let fileSize :Int? = try? FileManager.default.attributesOfItem(atPath: inFilePath)[FileAttributeKey.size] as? Int;
        
        let  minDlt =  Int(Double(fileSize!) * 0.01);
        var checked = 0;
        var currentDlt = 0
        
        
        print("");
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
        
        var cryptor : CCCryptorRef?
        
        _ = dataIv!.withUnsafeBytes({ bf  in
            CCCryptorCreate(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), dhHash, kCCKeySizeAES256, bf.baseAddress, &cryptor);
        })
        
        readLen = streamIn.read(buffer, maxLength: BufferSize);
        var currentDecrypt = 0
        var currentDelt = 0
        while readLen > 0{
            CCCryptorUpdate(cryptor,buffer,readLen,&dataOut,dataOutAvailable,&dataOutLen)
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
        CCCryptorFinal(cryptor, &dataOut, dataOutAvailable, &dataOutLen);
        
        if dataOutLen > 0 {
            streamOut.write(&dataOut, maxLength: dataOutLen);
            
        }
        _printProgress("decrypt",1.0)
        print("")
        CCCryptorRelease(cryptor);
        
        if tmpFile != nil && type == 0 {
            print("unzipping, please wait...");
            fflush(stdout)
            ungzipFile(infilePath: tmpFile!, outfilePath: realOutPath)
            print("\rUnzipping Done                                 " );
        }
        
        
        streamIn.close();
        streamOut.close();
        if(tmpFile != nil && type == 0){
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
    
    func ecEncryptFile(filePath:String,outFilePath:String?,pubkeyString:String,gzip:(Bool) = true) throws{
        var inFilePath = dealPath(filePath);
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
        var publen = 65;
        var outPub = [UInt8](repeating: 0, count: publen);
        var pubkey = secp256k1_pubkey();
        let dataPub = try! LTBase64.base64Decode(pubkeyString)
        try dataPub.withUnsafeBytes { bf  in
            let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count)
            let r = secp256k1_ec_pubkey_parse(self.ctx, &pubkey,p!,bf.count);
            guard r != 0 else{
                throw LECCError.createPublicKeyFail
            }
        }
        
        var randKey = [UInt8](repeating: 0, count: kECPrivateKeyByteCount);
        genSecKey(&randKey);
        defer{
            randBuffer(&randKey, kECPrivateKeyByteCount);
        }
        var randomPub = secp256k1_pubkey();
        try randKey.withUnsafeBufferPointer { bf  in
            let r = secp256k1_ec_pubkey_create(self.ctx,&randomPub,bf.baseAddress!)
            guard r == 1 else{
                throw LECCError.createPublicKeyFail
            }
        }
        
        let ecdhresul = secp256k1_ecdh(self.ctx,&dhHash,&pubkey,&randKey,my_ecdh_hash_function,nil);
        guard ecdhresul == 1 else{
            throw LECCError.EncryptECDHFail
        }
        /// no need anymore, reset the buffer
        genSecKey(&randKey);
        
        secp256k1_ec_pubkey_serialize(self.ctx,&outPub,&publen,&randomPub,SECP256K1_EC_COMPRESSED)
        
        var macPostion = 0
        var macBuffer = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        var iv = [UInt8](repeating: 0, count: Int(kCCBlockSizeAES128))
        randBuffer(&iv , iv.count)
        var ivLen = UInt16(kCCBlockSizeAES128)
        var macLen = UInt16(CC_SHA256_DIGEST_LENGTH)
        var ephemPubLen = UInt16(publen);
        var Zero = UInt16(gzip ? 0 : 1);
         
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
        
        var cryptor:CCCryptorRef?
        var ctx:CCHmacContext = CCHmacContext();
        
        CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),CCOptions(kCCOptionPKCS7Padding), &dhHash, kCCKeySizeAES256, &iv, &cryptor);
        
        defer {
            CCCryptorRelease(cryptor);
            self.randBuffer(&dhHash, dhHash.count);
        }
        
        dhHash.withUnsafeBufferPointer { bf  in
            CCHmacInit(&ctx, CCHmacAlgorithm(kCCHmacAlgSHA256) , bf.baseAddress?.advanced(by: 32), 32);
        }
        CCHmacUpdate(&ctx,&iv,kCCBlockSizeAES128)
        CCHmacUpdate(&ctx,&outPub,publen);
        
        var readDateLen = 0;
        
        let buffersize = kCCBlockSizeAES128 << 10;
        let encbuffersize = buffersize + kCCBlockSizeAES128;
        
        
        let buffer = malloc(buffersize).bindMemory(to: UInt8.self, capacity: buffersize)
        let bufferEncry = malloc(encbuffersize).bindMemory(to: UInt8.self, capacity: encbuffersize);
        defer {
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
            CCCryptorUpdate(cryptor,buffer,readDateLen,bufferEncry,encbuffersize,&encsize)
            
            
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
        CCCryptorFinal(cryptor,bufferEncry,encbuffersize,&encsize);
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
    
    func test(){
#if DEBUG
#endif
    }

}

extension FileHandle : TextOutputStream {
  public func write(_ string: String) {
    guard let data = string.data(using: .utf8) else { return }
    self.write(data)
  }
}

func Lprint(_ msg:Any ... ,file:String = #file,name:String = #function, line :Int = #line){
    
    return
    
    var stderr = FileHandle.standardError
    print("\(name) line:\(line) :" ,to:&stderr);
    
    
    for i in msg{
        print(i , separator:"", terminator: " ",to:&stderr);
    }
    print("",to:&stderr);
    
}


