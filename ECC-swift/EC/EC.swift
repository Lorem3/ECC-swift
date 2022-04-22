//
//  EC.swift
//  ECC-swift
//
//  Created by wei li on 2022/4/13.
//

import Foundation
import Accelerate
import CommonCrypto


enum EC_Err :Error{
    case PubkeyLengthError
    case PubkeyFormatError
    case PubkeyDataError
    
    case SeckeyDataError
    case SeckeyDataNotValid
}

typealias ECPubKey = EC.Point;
/// little-endian Interger
typealias ECSecKey = UnsafeMutableRawPointer
typealias ECKeyPair = (pubKey:String,priKey:String)


class EC{
    let pubKeyBufferLength = 33;
    let secKeyBufferLength = 32;
    private let XBufferLength = 32
    typealias NU512 = vU512;
    struct Point{
        var x:NU512
        var y:NU512
        init(_ x:NU512,_ y:NU512){
            self.x = x ;
            self.y = y
        }
    }
    
//    typealias Point = (x:NU512,y:NU512)
    let Prime:NU512
    let Order:NU512
    let G:Point
    // here we choose (0,0) which is not on the curve
    let ZeroPoint:Point
    
    
    /// cuve y^2 = x^3 + a x^2 + b ;
    /// here in sep256k1
    /// a = 0 b = 7
    let a : NU512 ;
    let b : NU512;
    
    
    ///
    internal let NZero:NU512;
    
    init(){
        let zero = vUInt32.zero;
        let zero256 =  NU512(v: (zero, zero,zero,zero))
        NZero = zero256;
        /*
        Prime = NU512(u32: 6741313)
        Order = NU512(u32: 1685701)
        G = Point(NU512(u32:2331692),NU512(u32:6255336))
         */
        
        // sep256k1
//      P   FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
//   ORDER   FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        
        var arr = [UInt32](repeating: 0, count: 16);
        arr[0] = 0xFFFFFC2F;
        arr[1] = 0xFFFFFFFE;
        arr[2] = 0xFFFFFFFF;
        arr[3] = 0xFFFFFFFF;
        arr[4] = 0xFFFFFFFF;
        arr[5] = 0xFFFFFFFF;
        arr[6] = 0xFFFFFFFF;
        arr[7] = 0xFFFFFFFF;
        Prime =  NU512(bytes: &arr, count: 64);
        
        arr[0] = 0xD0364141;
        arr[1] = 0xBFD25E8C;
        arr[2] = 0xAF48A03B;
        arr[3] = 0xBAAEDCE6;
        arr[4] = 0xFFFFFFFE;
        arr[5] = 0xFFFFFFFF;
        arr[6] = 0xFFFFFFFF;
        arr[7] = 0xFFFFFFFF;
        
        Order =  NU512(bytes: &arr, count: 64);
        
        
        
        // 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
        // 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
        var arrGx = [UInt32](repeating: 0, count: 64);
        arrGx[0] = 0x16F81798
        arrGx[1] = 0x59F2815B
        arrGx[2] = 0x2DCE28D9
        arrGx[3] = 0x029BFCDB
        arrGx[4] = 0xCE870B07
        arrGx[5] = 0x55A06295
        arrGx[6] = 0xF9DCBBAC
        arrGx[7] = 0x79BE667E
        
        var arrGy = [UInt32](repeating: 0, count: 64);
        arrGy[0] = 0xFB10D4B8
        arrGy[1] = 0x9C47D08F
        arrGy[2] = 0xA6855419
        arrGy[3] = 0xFD17B448
        arrGy[4] = 0x0E1108A8
        arrGy[5] = 0x5DA4FBFC
        arrGy[6] = 0x26A3C465
        arrGy[7] = 0x483ADA77
        
        let Gx = NU512(bytes: &arrGx, count: 64);
        let Gy = NU512(bytes: &arrGy, count: 64);
        
        G = Point(Gx,Gy)
        ZeroPoint = Point(zero256,zero256);
        a = NU512(u32: 0);
        b = NU512(u32: 7);
    }
    
    func serializeSecKeyBytes(_ bytes  :UnsafeRawPointer) -> String{
        var data = Data(repeating: 0, count: secKeyBufferLength);
        /// big Endian
        for i in 0..<secKeyBufferLength{
            let v = bytes.load(fromByteOffset: secKeyBufferLength - 1 - i , as: UInt8.self);
            data[i ] = v;
        }
        let r = data.base64EncodedString();
        data.resetBytes(in: 0..<data.count)
        return r ;
    }
    
    func serializeSecKey(_ sec:NU512) -> String{
        var data = Data(repeating: 0, count: secKeyBufferLength);
        let bytes = sec.to32Bytes();
        
        /// big Endian
        for i in 0..<bytes.count{
            data[i ] = bytes[secKeyBufferLength - 1 - i];
        }
        return data.base64EncodedString();
    }
    func serializePubKey(_ pub:ECPubKey,toBytes:UnsafeMutableRawPointer){
        let bytes = pub.x.to32Bytes();
        let p = toBytes.bindMemory(to: UInt8.self, capacity: pubKeyBufferLength);
        if pub.y.isOdd() {
            p[0] = 3;
        }else{
            p[0] = 2;
        }
        
        for i in 0..<secKeyBufferLength{
            p[i + 1] = bytes[secKeyBufferLength - 1 - i ];
        }
    }
    func serializePubKey(_ pub:ECPubKey) -> String{
        var bf = [UInt8](repeating: 0, count: pubKeyBufferLength);
        serializePubKey(pub , toBytes: &bf);
        let data = Data(bytesNoCopy: &bf , count: pubKeyBufferLength, deallocator: Data.Deallocator.none);
        return data.base64EncodedString();
    }
    
    /// big-Endian
    func readSecKey(_ base64String:String,keyOut:ECSecKey) throws {
        let data = try LTBase64.base64Decode(base64String)
        
        return  try  data.withUnsafeBytes { bf in
            if bf.count == secKeyBufferLength{
                var Xbuff = [UInt8](repeating: 0, count: secKeyBufferLength);
                memcpy(&Xbuff,bf.baseAddress!, secKeyBufferLength);
                Xbuff.reverse()
                
                if !isSecKeyByteValid(byte32: Xbuff) {
                    throw EC_Err.SeckeyDataError
                }
                
                memcpy(keyOut, Xbuff, secKeyBufferLength);
                Xbuff.resetBytes(in: 0..<Xbuff.count);
                
            }else{
                throw EC_Err.SeckeyDataError
            }
        }
    }
    
    func readPubKey(_ buffer:UnsafeRawPointer, count:Int) throws -> ECPubKey{
        if(count == 33){
            let bf = buffer.bindMemory(to: UInt8.self, capacity: count);
            let first = bf[0];
            if(first == 2 || first == 3){
                var Xbuff = [UInt8](repeating: 0, count: secKeyBufferLength);
                memcpy(&Xbuff,bf.advanced(by: 1), secKeyBufferLength);
                /// pubkey is big endian
                Xbuff.reverse();
                let x = NU512(bytes: &Xbuff, count: secKeyBufferLength);
                let P = getPoint(x: x,odd: first == 3);
                
                Xbuff.resetBytes(in: 0..<Xbuff.count);
                
                
                return P;
            }
            
            throw EC_Err.PubkeyFormatError
        }else if(count == 65){
            let bf = buffer.bindMemory(to: UInt8.self, capacity: count);
            let first = bf[0];
            if(first == 4){
                var numberBuffer = [UInt8](repeating: 0, count: XBufferLength);
                memcpy(&numberBuffer, bf.advanced(by: 1), XBufferLength);
                numberBuffer.reverse();
                
                let x = NU512(bytes: &numberBuffer, count: XBufferLength);
                memcpy(&numberBuffer, bf.advanced(by: 33), XBufferLength);
                numberBuffer.reverse();
                let y = NU512(bytes: &numberBuffer, count: XBufferLength);
                let P = getPoint(x: x,odd: y.isOdd());
                
                if(P.y == y){
                    return P;
                }
                throw EC_Err.PubkeyDataError
            }
            throw EC_Err.PubkeyFormatError
        }else{
            throw EC_Err.PubkeyLengthError
        }
    }
    func readPubKey(_ base64str:String) throws -> Point{
        let data = Data(base64Encoded: base64str)!;
        
        return data.withUnsafeBytes { bf  in
            return try! readPubKey(bf.baseAddress!, count: bf.count);
        }
    }
    
    /// here we just return 1 Point the other y2 = Prime - y1
    func getPoint(x:NU512 ,odd:Bool = true) -> (Point){
        // y^2 = x^3 + ax + b mod Prime
        let k = (((x * x % Prime) * x) % Prime + a * x + b) % Prime;
        let y = k.cipolla_sqrt(P: Prime);
        
        
        if odd != (y.intValue & 1 == 1){
            return Point(x,Prime - y)
        }
        return Point(x,y)
        
        
    }
    
    func pointAdd(P:Point,Q:Point,R:inout Point){
        if(isZeroPoint(P)){
            R = Q;
        }
        if(isZeroPoint(Q)){
            R = P;
        }
        
        
        var k:NU512
        /// 求切线
        if P == Q{
            if isZeroPoint(P){
                R = ZeroPoint;
                return;
            }
            
            let tmp = (P.y * 2).exGCD(Prime);
            k = ((((P.x * P.x % Prime) * 3 + a) % Prime) * tmp) % Prime
            
      
        }else{
            if P.x == Q.x{
                R = ZeroPoint;
                return;
            }
            
            let tmpz = (P.x + Prime - Q.x) % Prime
            let tmp = tmpz.exGCD(Prime);
            let tmpDy = (P.y + Prime - Q.y) % Prime

            k = (tmpDy * tmp) % Prime
             
        }
        var x = ((k  * k)  - P.x - Q.x) % Prime
        if x .isNegtive() {
            x = -x;
        }
        
        let y = ((k * ((P.x + Prime - x ) % Prime)) % Prime + Prime - P.y) % Prime;
 
        R = Point(x,y)
        
    }
    
    
    func pointTimes(P:Point, s:NU512)-> Point{
        let s1 = s % Order
        var R = Point(NU512.zeroN(),NU512.zeroN());
         _pointTimes(P: P, s: s1,R:&R);
        return R;
    }
    
    internal func _pointTimes(P:Point, s:NU512,R: inout Point){
        if s == 0{
            R = ZeroPoint
            return;
        }
        if s == 1{
            R = P
            return;
        }
        
        if s == 2{
            pointAdd(P: P , Q: P , R: &R)
            return;
        }
        
        
        let  s_2 = s / 2;
 
        _pointTimes(P: P , s: s_2, R: &R);
        pointAdd(P: R , Q: R , R: &R)
        if s.isOdd() {
            pointAdd(P: R , Q: P , R: &R)
        }
    }
    
    
    /**
     *  SecKey > 0 && SecKey < Order
     */
    func isSecKeyByteValid(byte32:UnsafeRawPointer)->Bool{
        
        let order = Order.to32Bytes();
//        let D1 = Data(bytes: order, count: 32)
//        let D2 = Data(bytes: byte32, count: 32)
//        print("D1-Order0 ",Order.hexString());
//        print("D1-Order_ ",D1.tohexString());
//        print("D2_SecKey ",D2.tohexString());
         
        var isSmallerThanOrder = false
        var isZero = true
        for n in 0..<secKeyBufferLength{
            let i = secKeyBufferLength - 1 - n ;
            let v1 = byte32.load(fromByteOffset: i , as: UInt8.self)
            if v1 < order[i]{
                isSmallerThanOrder = true
                break;
            }
        }
        for i in 0..<secKeyBufferLength{
            if byte32.load(fromByteOffset: i , as: UInt8.self) != 0{
                isZero = false;
                break;
            }
        }
        return !isZero && isSmallerThanOrder;
    }
    
    func signData(seckey:ECSecKey,data32:UnsafeRawPointer,out64:UnsafeMutableRawPointer){
        /// big-endian
        var bfHash = [UInt8](repeating: 0, count: 32);
        var bfTmpR = [UInt8](repeating: 0, count: 32);
        var bfTmp = [UInt8](repeating: 0, count: 32);
        defer{
            bfTmpR.resetBytes(in: 0..<bfTmpR.count);
            bfHash.resetBytes(in: 0..<bfTmpR.count);
            bfTmp.resetBytes(in: 0..<bfTmpR.count);
            
        }
        
        memcpy(&bfHash, data32, 32);
        bfHash.reverse();
        let h = NU512(bytes: &bfHash, count: 32);
        
        var Rx :NU512 = NU512.zeroN() ;
        var retry = false;
        repeat{
            retry = false;
            arc4random_buf(&bfTmp , 32);
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),&bfTmp ,32,data32,32,&bfTmpR);
            if !isSecKeyByteValid(byte32: bfTmpR){
                retry = true
                continue;
            }
            
            let  tmpPubKey = try! createPubKey(secBytes32: &bfTmpR);
            Rx = tmpPubKey.x
            
            if Rx == 0 {
                retry = true;
                continue;
            }
            retry = !isSecKeyByteValid(byte32: bfTmpR)
            
            let k = NU512(bytes: bfTmpR, count: secKeyBufferLength)
            let k1 = k.exGCD(Order);
            
            var privateKey = NU512(bytes: seckey, count: secKeyBufferLength);
            defer{
                privateKey.clear()
            }
            let sign = (k1 * ( (h + privateKey * Rx ) % Order)) % Order;
            var rxArr =  Rx.to32Bytes()
            rxArr.reverse()
            var signArr =  sign.to32Bytes()
            signArr.reverse()
             
            let pOut = out64.bindMemory(to: UInt8.self, capacity: 64);
            for i in 0..<32{
                pOut[i] = rxArr[i];
                pOut[i + 32] = signArr[i];
            }
            
             
        }while retry
        /// S =  k  (h + dA • Rx)
    }
    
    func verifySignature(pubKey:ECPubKey,hash:UnsafeRawPointer, signData64:UnsafeMutableRawPointer) -> Bool{
        var SignData = [UInt8](repeating: 0, count: 64);
        var Hash = [UInt8](repeating: 0, count: 32);
        defer{
            SignData.resetBytes(in: 0..<SignData.count)
        }
        memcpy(&SignData, signData64, 64);
        SignData.reverse()
        
        memcpy(&Hash, hash, 32);
        Hash.reverse();
        
        let h = NU512(bytes: &Hash, count: 32);
     
        var  S :NU512 = NU512.zeroN();
        var  Rx:NU512 = NU512.zeroN();
        SignData.withUnsafeBytes { bf  in
            S = NU512(bytes: bf.baseAddress!, count: 32)
            Rx = NU512(bytes: bf.baseAddress!.advanced(by: 32), count: 32)
        }
        //  R =  s1 (h G  + P • Rx)
        let s1 = S.exGCD(Order)
        let P2 = pointTimes(P: G , s: h)
        let P3 = pointTimes(P: pubKey , s: Rx)
        
        var R = ZeroPoint;
        pointAdd(P: P2 , Q: P3 , R: &R)
        R = pointTimes(P: R , s: s1);
        return R.x == Rx
    }
    
    /// sha512(DH.X)
    func ecdh(secKeyA: ECSecKey,pubKeyB:ECPubKey,outBf64:UnsafeMutableRawPointer){
        
        var s = NU512(bytes: secKeyA, count: secKeyBufferLength);
        let dh = pointTimes(P: pubKeyB, s: s);
        s.clear();
        
        var x32 = dh.x.to32Bytes()
        // big-endian
        x32.reverse();
        CC_SHA512(x32, CC_LONG(XBufferLength), outBf64.bindMemory(to: UInt8.self, capacity: XBufferLength));
        x32.resetBytes(in: 0..<x32.count)
    }
    
    func generateKeyPair(_ secKey:String? = nil) -> ECKeyPair{
        var keyBuffer = [UInt8].init(repeating: 0, count: secKeyBufferLength);
        generateSecBytes(outBf32: &keyBuffer)
        
        let secKey = NU512(bytes: &keyBuffer , count: secKeyBufferLength);
        let pubKey = pointTimes(P: G , s: secKey);
        
        keyBuffer.reverse();
        let data = Data(bytesNoCopy: &keyBuffer, count: keyBuffer.count, deallocator: Data.Deallocator.none)
        
        let strKey = data.base64EncodedString();
        keyBuffer.resetBytes(in: 0..<keyBuffer.count);
        
        let pubkeyStr = serializePubKey(pubKey);
        return (pubKey:pubkeyStr,priKey:strKey)
    }
    
    func generateSecBytes(outBf32:UnsafeMutableRawPointer){
        
        var tmp:[UInt8] = [UInt8](repeating: 0 , count: 64);
        var tmpdata:[UInt8] = [UInt8](repeating: 0 , count: 128);
        
        repeat{
            arc4random_buf(&tmp , 64);
            arc4random_buf(&tmpdata , 128);
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),tmp ,64,tmpdata,128,outBf32);
        }while !isSecKeyByteValid(byte32: outBf32)
    }
    func createPubKey(secBytes32:ECSecKey) throws -> ECPubKey{
        
        if !isSecKeyByteValid(byte32: secBytes32){
            throw EC_Err.SeckeyDataNotValid
        }
        var s = NU512(bytes: secBytes32, count: secKeyBufferLength);
        let P = pointTimes(P: G , s: s);
        s.clear()
        
        return P;
    }

    
}




/// mark do the mac

extension EC {
     
    /// (0,0) is not on sep256k1, so we treat it as ZeroPoit
    @inline(__always)func isZeroPoint(_ P:Point) -> Bool{
        return ZeroPoint == P;
    }
     
    
    func clearNU512(_ a:inout NU512){
        a.v.0 = SIMD4<UInt32>.zero;
        a.v.1 = SIMD4<UInt32>.zero;
    }
    
}

extension EC.Point{
    @inline(__always) static func == (_ P:EC.Point,_ Q: EC.Point ) ->Bool{
        return P.x == Q.x && P.y == Q.y
    }
    @inline(__always) static func != (_ P:EC.Point,_ Q: EC.Point ) ->Bool{
        return  !(P == Q);
    }
}



extension EC.NU512{
    typealias NU512 = EC.NU512
    
    typealias NS512 = vS512
    
    /// little endian
    init(  bytes:UnsafeRawPointer,count:Int){
        self.init();
        self.fill(bytes:bytes, count: count);
    }
    /// max count = 32;
    mutating func  fill(bytes:UnsafeRawPointer,count:Int){
        for i in 0..<count{
            let sIndx = i / 16;
            let byteIdx = i % 4;
            
            let itemIdx = (i % 16) / 4
            switch sIndx {
            case 0:
                var simd = self.v.0;
                
                var v = simd[itemIdx];
                let i8 = bytes.load(fromByteOffset: i , as: UInt8.self);
                let i32 = UInt32(i8) << (byteIdx * 8)
                v |= i32;
                simd[itemIdx] = v;
                self.v.0 = simd;
                
                
                break
            case 1:
                var simd = self.v.1;
                var v = simd[itemIdx];
                let i8 = bytes.load(fromByteOffset: i , as: UInt8.self);
                let i32 = UInt32(i8) << (byteIdx * 8)
                v |= i32;
                simd[itemIdx] = v;
                self.v.1 = simd;
                
                break
            case 2:
                var simd = self.v.2;
                var v = simd[itemIdx];
                let i8 = bytes.load(fromByteOffset: i , as: UInt8.self);
                let i32 = UInt32(i8) << (byteIdx * 8)
                v |= i32;
                simd[itemIdx] = v;
                self.v.2 = simd;
                break
            case 3:
                var simd = self.v.3;
                var v = simd[itemIdx];
                let i8 = bytes.load(fromByteOffset: i , as: UInt8.self);
                let i32 = UInt32(i8) << (byteIdx * 8)
                v |= i32;
                simd[itemIdx] = v;
                self.v.3 = simd;
                break
            default:
                
                Lprint("Error Max Lenght 32")
                break
            }
             
        }
    }
    
    @inline(__always)static func == (_ x:NU512,_ y:NU512) -> Bool{
        return x.v.0 == y.v.0 && x.v.1 == y.v.1 && x.v.2 == y.v.2 && x.v.3 == y.v.3
    }
    
    @inline(__always)static func == (_ x:NU512,_ y:UInt32) -> Bool{
        return x.v.0[0] == y
        && x.v.0[1] == 0
        && x.v.0[2] == 0
        && x.v.0[3] == 0
        && x.v.1 == vUInt32.zero
        && x.v.2 == vUInt32.zero
        && x.v.3 == vUInt32.zero
    }
    
    
    @inline(__always) static func zeroN() -> NU512{
        let zero = vUInt32.zero;
        let zero256 =  NU512(v: (zero, zero,zero,zero))
        return zero256;
    }
    
    @inline(__always) static func oneN() -> NU512{
        let zero = vUInt32.zero;
        var one = vUInt32.zero;
        one[0] = 1;
        let z =  NU512(v: (one, zero,zero,zero))
        return z;
    }
    
    
    
    @inline(__always) func isSameNumber(_ y:NU512) -> Bool{
        return self.v.0 == y.v.0 && self.v.1 == y.v.1 && self.v.2 == y.v.2 && self.v.3 == y.v.3
    }

      
    
    /// a * X = 1 mod p
    func getInverseModOf(p:NU512){
        /**
         * from Fermat's little theorem we know tha  a  ^(p-1) = 1 mod p where p is prime number  and a % p != 0
         * so  we just return a ^ (p-2)
         *
         * is p is not prime number, we use exGcd
         */
         
        
    }
    
    
    ///   x ^ 2 = a mod P
    ///  if x exsist return true
    func eulerJudge(a:NU512,p:NU512) -> Bool{
        
        if a % p == 0 {
            return true;
        }
        
        let b = (p - NU512.oneN()) / 2;
        var s = NU512.zeroN();
        var k = 0
        
        b.removeAllRightZero(result: &s, zeroBitCount: &k)
       
        var t = pow(a: a , x: s , p: p);
        if t == 1{
            return true
        }
        
        var k0 = 0;
        while k0 < k {
            t = (t * t) % p;
            if t == 1{
                return true
            }
            
            k0 += 1
        }
        
        
//        let p1 = p - NU512.oneN()
        
        return t == 1
        

    }
    
    func pow(a:NU512,x:NU512,p:NU512) -> NU512{
        var R = NU512.zeroN()
        _pow(a: a, x: x , p: p , R: &R);
        return R;
    }
    
    internal func _pow(a:NU512,x:NU512,p:NU512,R:inout NU512){
        if( a == 0){
            R = NU512.zeroN();
            return;
        }
        if x == 1{
            R = a % p;
            return;
        }
        
        if x == 0{
            R = NU512.oneN()
            return;
        }
        
        let x_2 = x / 2;
        let s_a = x.intValue & 1;
        
        _pow(a: a, x: x_2, p: p, R: &R);
        
        let r0 = R;
        R = (R * R) % p;
       
        
        if(s_a == 1){
            R = (R * a) % p
        }
        
    }
    
    func multiply(_ a:NU512,_ b:NU512,_ p:NU512) -> NU512{
        let a_2 = a / 2;
        let s = a.intValue & 1;
        
        var r = ((a_2 * b ) % p * 2) % p
        if s == 1{
            r = (r + b) % p
        }
        return r;
        
    }
    
    
    typealias ComplexNum = (x:NU512,y:NU512)
    
    /// find x ^ 2 = self mode P
    func cipolla_sqrt(P:NU512) -> NU512{
        let n = self;
        if n == 0{
            return NU512.zeroN()
        }
        
        if !eulerJudge(a:n,p:P){
            
            return NU512.zeroN()
        }
        
        var a = NU512.zeroN()
        var A2_N = NU512.zeroN()
        
        repeat{
            a = NU512(u32: arc4random_uniform(10000) + 1) ;//
            A2_N = (a * a + P - n + P) % P
        }while eulerJudge(a: A2_N, p: P)
        
        let n1 = NU512(u32: 1);
        let r = pow2((x:a,y:n1), A2_N, (P + n1) / 2, P);
        return r.x % P;
    }
    
    func pow2(_ xy:ComplexNum,_ A2_N:NU512,_ k:NU512,_ p:NU512) -> ComplexNum{
        var R = ComplexNum(x:NU512.zeroN(),y:NU512.zeroN());
        _pow2(xy , A2_N, k , p , &R);
        return R;
        
    }
    
    func _pow2(_ xy:ComplexNum,_ A2_N:NU512,_ k:NU512,_ p:NU512,_ Result:inout ComplexNum){
        
        if k == 1{
            Result = xy
            return ;
        }else if(k == 2){
            comlexMultiply(xy,xy,A2_N,p,&Result)
            return;
        }
        
        let left = k.v.0[0] & 1;
        let k_2 = k / 2;
        _pow2(xy, A2_N, k_2, p , &Result);

        comlexMultiply(Result,Result,A2_N,p,&Result)
        
        if(left == 1){
            
            comlexMultiply(Result,xy,A2_N,p,&Result)
        }else{
            
        }
        
    }
    
    
    static var xx :Int32 = 0
    func comlexMultiply(_ X1:ComplexNum,_ X2:ComplexNum,_ A2_N:NU512,_ p:NU512,_ Result:inout ComplexNum) {
        
        
        let x = ((X1.x * X2.x) % p + (X2.y * ((X1.y   * A2_N) % p)) % p) % p
        let y = (((X1.x * X2.y) % p + ((X1.y * X2.x) % p)) % p) % p;
    
       
        Result = (x,y);
    }
    
    
    
    
     
    
    /// find x than  self * x = 1 mod P;
    func exGCD(_ P: NU512) -> NU512{
        let a = self;
        
        if a == 1{
            return NU512.oneN()
        }
        if a == 0{
            return NU512.zeroN();
        }
        
        var aa = a;
        
        aa = aa % P;
        

        
        var P2 = P;
        let m = _exGCD(a: &aa , b: &P2);
        let r0:NU512
        
        
        
        if m.0.isNegtive == 1{
            r0 =  (-m.0.value  + P) % P
        }else{
            r0 = (m.0.value % P  + P) % P ;
            
        }
        return r0
        
        
        
        
        
        
    }
    
   
    
    typealias NSign512 = (isNegtive:Int,value:NU512)
    typealias Matrix4 = (NSign512,NSign512,NSign512,NSign512)
    ///
    func _exGCD(a:inout NU512,b:inout NU512) -> Matrix4 {
         
        
         // a * x = b mod 1;
        /**
         *    | xn  1 |  ... | x1  1|    |a |  = |1|
         *    | 1   0 |      | 1   0|    | b|    |k|
         */
        
        var s = b % a;

        var q = NU512.zeroN();
        b.divide(a, result: &q , remain: &s);

        if s == 1{
            
            return (
                (1,q),
                (0,NU512.oneN()),
                (0,NU512.oneN()),
                (0,NU512.zeroN()))
            
            
//            return ((-q),NU512.oneN(),NU512.oneN(),NU512.zeroN())
        }

        else if s == 0 {
            
            return (
                (0,NU512.zeroN()),
                (0,NU512.zeroN()),
                (0,NU512.zeroN()),
                (0,NU512.zeroN())
            )
            
//            return (NU512.zeroN(),NU512.zeroN(),NU512.zeroN(),NU512.zeroN())
        }

        
        let m0 = (
            (1,q),
            (0,NU512.oneN()),
            (0,NU512.oneN()),
            (0,NU512.zeroN())
        )
        
//        let m0 = (( -q),NU512.oneN(),NU512.oneN(),NU512.zeroN());
        let m1 = _exGCD(a: &s , b: &a );
        
        return MtrixMultiply(m0,m1)
    }
    
    func ns_multiply( a:NSign512, b:NSign512) -> NSign512{
        return (isNegtive:a.isNegtive == b.isNegtive ? 0:1,value:a.value * b.value)
    }
    
    func ns_add(_ a:NSign512,_ b:NSign512) -> NSign512{
        if a.isNegtive == b.isNegtive{
           return  (isNegtive:a.isNegtive ,value:a.value + b.value)
        }else{
            let r = a.value - b.value;
            if r.isNegtive(){
                return (isNegtive:b.isNegtive ,-r)
            }else{
                return (isNegtive:a.isNegtive ,r)
            }
            
        }
    }
    
    func MtrixMultiply(_ a:Matrix4,_ b:Matrix4) -> Matrix4{
        /*
          a0 a1           b0 b1
          a2 a3     *     b2 b3
         */
        
        
        
        return (
            ns_add(ns_multiply(a: a.0, b: b.0), ns_multiply(a: a.1, b: b.2)),
            ns_add(ns_multiply(a: a.0, b: b.1), ns_multiply(a: a.1, b: b.3)),
            ns_add(ns_multiply(a: a.2, b: b.0), ns_multiply(a: a.3, b: b.2)),
            ns_add(ns_multiply(a: a.2, b: b.1), ns_multiply(a: a.3, b: b.3)))
        
        
//        return (a.0 * b.0 + a.1 * b.2,
//                a.0 * b.1 + a.1 * b.3,
//                a.2 * b.0 + a.3 * b.2,
//                a.2 * b.1 + a.3 * b.3)
    }
    
   
}





