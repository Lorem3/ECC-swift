//
//  Tools.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/16.
//

import Foundation
import zlib
enum GzErrorCode :Int {
    case decompressFail = 0
    case compressFail = 1
}

struct GZIPError :Error{
    let message :String?;
    let type : GzErrorCode;
    init(_ code:GzErrorCode, _ message: String = ""){
        self.type = code;
        self.message = message;
    }
}



extension Data {
    func tohexString() -> String{
        let hexAlphabet = Array("0123456789abcdef".unicodeScalars)
        let rd = reduce(into: "".unicodeScalars) { r, e  in
            r.append(hexAlphabet[Int(e / 0x10)])
            r.append(hexAlphabet[Int(e % 0x10)])
        };
        return String(rd);
    }
    
    func sha256(base64:Int = 0) -> String{
        let lenOfDgst = Int(CC_SHA256_DIGEST_LENGTH);
        var outData = Data(repeating: 0, count: lenOfDgst)
        
        _ = self.withUnsafeBytes { bf  in
            outData.withUnsafeMutableBytes { bfOut in
                CC_SHA256(bf.baseAddress, CC_LONG(self.count), bfOut.baseAddress?.bindMemory(to: UInt8.self, capacity: bfOut.count));
            }
        };
        
        if base64 == 1 {
            return outData.base64EncodedString();
        }else{
            return outData.tohexString();
        }
    }
    func md5String(base64:Int = 0)->String{
        
        let lenOfDgst = Int(CC_MD5_DIGEST_LENGTH);
        var outData = Data(repeating: 0, count: lenOfDgst)
        
        _ = self.withUnsafeBytes { bf  in
            outData.withUnsafeMutableBytes { bfOut in
                CC_MD5(bf.baseAddress, CC_LONG(self.count), bfOut.baseAddress?.bindMemory(to: UInt8.self, capacity: bfOut.count));
            }
        };
        
        if base64 == 1 {
            return outData.base64EncodedString();
        }else{
            return outData.tohexString();
        }
        
    }
    
    
    func gzipCompress() throws -> Data{
        
        if (self.isEmpty) {
            return Data();
        }
        
        var  strm = z_stream();
        strm.total_out = 0;
        strm.avail_in = uInt(self.count);
        let GZIP_STREAM_SIZE: Int32 = Int32(MemoryLayout<z_stream>.size)
        if (deflateInit2_(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          (15+16), 8, Z_DEFAULT_STRATEGY,ZLIB_VERSION,GZIP_STREAM_SIZE) != Z_OK){
            throw GZIPError(GzErrorCode.compressFail,"initFail");
        }
        
        let chunk = 16384
        var compressed = Data(capacity: chunk);
        var status:Int32 = 0;
        repeat {
            if Int(strm.total_out) >= compressed.count {
                compressed.count += chunk
            }
            let inputCount = self.count;
            let outputCount = compressed.count;
            
            self.withUnsafeBytes { bf  in
                strm.next_in = UnsafeMutablePointer(mutating:bf.baseAddress?.bindMemory(to: UInt8.self, capacity:inputCount).advanced(by: Int(strm.total_in)));
                
                compressed.withUnsafeBytes { bf  in
                    strm.next_out = UnsafeMutablePointer(mutating:bf.baseAddress!.bindMemory(to: UInt8.self, capacity: outputCount).advanced(by: Int(strm.total_out)));
                    strm.avail_out = uInt(outputCount) - uInt(strm.total_out)
                    status = deflate(&strm, Z_FINISH)
                    strm.next_out = nil;
                }
            }
            
            strm.next_in = nil;
            
            
        } while (strm.avail_out == 0);
        
        guard deflateEnd(&strm) == Z_OK, status == Z_STREAM_END else {
            throw GZIPError(GzErrorCode.compressFail);
        }
        compressed.count = Int(strm.total_out)
        return compressed
    }
    func gzipDecompress()  throws -> Data {
        
        if self.isEmpty  {
            return Data();
        }
        
        let GZIP_STREAM_SIZE: Int32 = Int32(MemoryLayout<z_stream>.size)
        
        let full_length = self.count;
        let half_length = self.count / 2;
        
        var decompressed = Data(capacity: full_length + half_length );
        
        var done = false
        var status : Int32 = Z_OK;
        
        var  strm = z_stream();
        
        strm.avail_in = uInt(self.count);
        strm.total_out = 0;
        strm.zalloc = nil;
        strm.zfree = nil;
        if (inflateInit2_(&strm, (15+32),ZLIB_VERSION,GZIP_STREAM_SIZE) != Z_OK) {
            throw GZIPError(GzErrorCode.decompressFail,"initFail");
        }
        
        repeat {
            if Int(strm.total_out) >= decompressed.count {
                decompressed.count += self.count / 2
            }
            let outputCount = decompressed.count;
            
            decompressed.withUnsafeMutableBytes { (bf:UnsafeMutableRawBufferPointer) in
                self.withUnsafeBytes { bfIn in
                    strm.next_in = UnsafeMutablePointer<UInt8> (mutating: bfIn.baseAddress?.bindMemory(to: UInt8.self, capacity: bfIn.count))?.advanced(by: Int(strm.total_in));
                }
                
                strm.next_out = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: bf.count).advanced(by: Int(strm.total_out));
                
                strm.avail_out = uInt(outputCount) - uInt(strm.total_out)
                status = inflate (&strm, Z_SYNC_FLUSH);
                
                if (status == Z_STREAM_END) {
                    done = true
                }
                else if (status != Z_OK) {
                    
                }
            }
            
        }while(!done)
        
        
        
        
        if (inflateEnd (&strm) != Z_OK) {
            throw GZIPError(GzErrorCode.decompressFail,"fail \(#line)");
        }
        
        // Set real length.
        if (done)
        {
            decompressed.count = Int(strm.total_out)
            return decompressed;
        }
        else{
            throw GZIPError(GzErrorCode.decompressFail,"fail \(#line)");
        }
        
    }
}



func redPrint(_ msg:Any,line:Int = #line,funcname:String = #function){
    print("\u{001B}[31;49m\(msg) \(funcname) \(line) \u{001B}[0;0m")
}
