//
//  Base64.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation

enum LTBase64Error: Error{
    case base64DecodeFail
}

class LTBase64 {
    static internal let map = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"];
    
    static internal var  invertMap = Array<UInt8>(repeating: UInt8.max, count: 128);
    
    static internal var isInvertMapInit = 0;
    
    static internal func initBase64DecodeMap(){
        if isInvertMapInit == 1{
            return ;
        }
        
        for i in 0...(map.count-1){
            let asc = map[i].first?.asciiValue;
            invertMap[ Int(asc!)] = UInt8(i);
        }
        return
    }
    
    @inlinable  internal static func convertUInt8ToBase64Code(_ i:UInt8) -> UInt8{
        let j = map[Int(i)];
        return j.first?.asciiValue ?? 0;
    }
    @inlinable  internal static  func uInt8ToChar(_ i:UInt8, preValue:UInt8 ,offset:Int,fourthChar: inout UInt8 )->UInt8{
        let bitsLeft = offset;
        let bitsCurrent = 6 - bitsLeft;
        
        let shift = (8 - bitsCurrent);
        let  v1 :UInt8 = ((0xff >> (8 - bitsLeft)) & preValue);
        let  v2 :UInt8 = ((0xff << shift) & i) >> shift ;
        let v = (v1 << (bitsCurrent)) | v2;
        // 010000 01  0100 0001
        if(bitsCurrent == 2){
            fourthChar = self.convertUInt8ToBase64Code(i & 0x3f);
        }
        
        return self.convertUInt8ToBase64Code(v);
        
    }
    
    @inlinable internal static func base64CodeToUInt8(_ char:Character,outValue:inout UInt8) -> Bool{
        self.initBase64DecodeMap();
        if(!char.isASCII ){
            return false;
        }
        
        let idx = Int(char.asciiValue!);
        if(idx >= invertMap.count){
            return false;
        }
        
        let c = self.invertMap[idx];
        if c == UInt8.max{
            return false;
        }
        outValue = c;
        return true;
    }
    static func base64Encode(_ source:Data)->String{
        let data  = source;
        let CountOfResult = (data.count / 3) * 4 + 4;
        var resultData = Data.init(capacity: CountOfResult);
        
        /// 前一个字符的未处理的bit
        var offset = 0;
        var preV  = 0 as UInt8;
        var fourth = 0 as UInt8;
        for v in data  {
            let v2  = self.uInt8ToChar(v , preValue: preV, offset: offset,fourthChar:&fourth);
            resultData.append(v2);
            if offset == 4 {
                resultData.append(fourth);
                offset = 0;
            }
            else{
                offset = 8 - (6 - offset);
            }
            preV = v;
        }
        
        if offset != 0{
            let v2  = self.uInt8ToChar(0 , preValue: preV, offset: offset,fourthChar:&fourth);
            resultData.append(v2);
            resultData.append(0x3d);
            if offset == 4 {
                offset = 0;
            }
            else{
                resultData.append(0x3d);
                offset = 8 - (6 - offset);
            }
        }
        let r = String.init(data: resultData, encoding: .ascii) ;
        return r!;
    }
    static func base64Encode(_ source:String) -> String{
        return self.base64Encode(source.data(using: String.Encoding.utf8)!)
    }
    
    
    @inlinable internal static func combineBase64Code2UInt8(_ currentValue: UInt8 , preValue:UInt8, bitsLeft:Int) -> UInt8{
        let bitsCur =  8 - bitsLeft;
        let vPre : UInt8 =  preValue & (0xff >> (8 - bitsLeft));
        /// 从第 6位开始
        /// 00 00 00 00
        let shift = (6 - bitsCur);
        let vCur : UInt8 =  (currentValue  & ((0x3f >> shift) << shift )) >> shift;
        
        let v = vCur | (vPre << bitsCur);
        return v;
    }
    
    static func base64Decode(_ base64Str:String) throws ->  Data{
        
        let base64 = base64Str;
        var preValue :UInt8 = 0;
        var value :UInt8 = 0;
        var leftBits : Int = 0;
        
        var data = Data(capacity: base64.count / 3 * 4 + 4)
        
        for c in base64{
            let r = base64CodeToUInt8(c,outValue: &value);
            if(!r){
                // skip
                continue;
            }
            
            if(leftBits == 0){
                preValue = value;
                leftBits = 6;
                continue;
            }
            else {
              let r =  combineBase64Code2UInt8(value , preValue: preValue, bitsLeft: leftBits);
                data.append(r);
                leftBits =  leftBits - 2;
                
                preValue = value;
            }
        }
        
        return data;
    }
    
    static func stringFromBase64(_ base64:String)throws -> String{
        let data = try base64Decode( base64);
        
        return  String(data: data , encoding:.utf8 )!;
    }
}

