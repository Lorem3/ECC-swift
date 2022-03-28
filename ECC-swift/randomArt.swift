//
//  randomArt.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/21.
//

private let RandomArtWidth : Int = 17;
private let RandomArtHeight : Int = 9;
private let RandomArtMapWidth = (RandomArtWidth + 3);
private let RandomArtMapHeight = (RandomArtHeight + 2);
private let RandomArtLen = RandomArtMapWidth * RandomArtMapHeight ;

@inline(__always) private  func indexBorderXY(_ x:Int,_ y:Int) -> Int{
    return ((x) + ((y) * RandomArtMapWidth));
}
@inline(__always) private  func indexXY(_ x:Int,_ y:Int) -> Int{
    return indexBorderXY((x+1), (y + 1));
}

private func valify(_ realX:inout Int,_ realY:inout Int){
    realX = max(0,realX);
    realX = min(RandomArtWidth - 1,realX);
    realY = max(0,realY);
    realY = min (RandomArtHeight - 1,realY);
}

private func goWithValue(direction:UInt8,x:inout Int,y:inout Int ,outChar:inout [UInt8]){
    var realX = x;
    var realY = y;
    switch direction {
    case 0:
        realX -= 1
        realY -= 1
    case 1:
        realX += 1
        realY -= 1
    case 2:
        realX -= 1
        realY += 1
    case 3:
        realX += 1
        realY += 1
    default:
        break;
    }
    valify(&realX, &realY);
    var v = outChar[indexXY(realX, realY)]
    v &+= 1;
    let j = indexXY(realX, realY)
    outChar[j] = v;
    
    x = realX
    y = realY
    
}



import Foundation
class RandomArt{
    
    static func randomArt(data:Data ,title:String?,end:String?)-> String{
        var outS = [UInt8](repeating: 0, count: RandomArtLen);
        data.withUnsafeBytes { bf  in
            let p = bf.baseAddress!;
            _randomArt(p ,hashLen:bf.count, title: title, end: end, outString: &outS);
        }
        
        
        let d = Data(bytes: &outS, count: outS.count);
        
        return String(data: d , encoding: .utf8)!
        
    }
    
    
    static private func _randomArt(_ hash:UnsafeRawPointer,hashLen:Int,title:String?,end:String?, outString:inout [UInt8]){
        
        let hash0 = hash.bindMemory(to: UInt8.self, capacity: hashLen);
        outString.replaceSubrange(0..<outString.count, with: repeatElement(0, count: outString.count));
        
        let startX : Int = RandomArtWidth/2;
        let startY : Int = RandomArtHeight/2;
        var x = startX,y = startY;
        for i  in 0..<hashLen {
            let tmp = hash0[i];
            
            var direction  = tmp & 3;
            goWithValue(direction: direction, x: &x , y: &y , outChar: &outString);
            direction = (tmp & (3 << 2)) >> 2 ;
            goWithValue(direction: direction, x: &x , y: &y , outChar:&outString)
                            
            direction = (tmp & (3 << 4)) >> 4 ;
            goWithValue(direction: direction, x: &x , y: &y , outChar:&outString)
            
            direction = (tmp & (3 << 6)) >> 6 ;
            goWithValue(direction: direction, x: &x , y: &y , outChar:&outString)
                            
        }
        
//        let startRealValue = outString[indexXY(startX, startY)];
//        let endRealValue = outString[indexXY(x, y)];
        
        outString[indexXY(startX, startY)] = 15;
        outString[indexXY(x, y)] = 16;
       
        
        let  Values : [UInt8] = " .o+=*BOX@%&#/^SE".map { c in
            return c.asciiValue!
        }
        let lenMax = Values.count;
        
        let FirstAscii =  { (s:Character)->UInt8 in
            return s.asciiValue!;
        }
        
        for i in 0..<RandomArtMapWidth {
            outString[indexBorderXY(i, 0)] = FirstAscii("-");
            outString[indexBorderXY(i ,RandomArtMapHeight - 1)] = FirstAscii("-");
        }
        
        for i in  0..<RandomArtMapHeight{
            outString[indexBorderXY(0, i)] = FirstAscii("|")
            outString[indexBorderXY(RandomArtMapWidth - 2, i)] = FirstAscii("|");
            outString[indexBorderXY(RandomArtMapWidth - 1, i)] = FirstAscii("\n");
        }
        
        outString[indexBorderXY(0,0)] = FirstAscii("+");
        outString[indexBorderXY(RandomArtMapWidth - 2,0)] = FirstAscii("+")
        
        outString[indexBorderXY(0,RandomArtMapHeight - 1)] = FirstAscii("+")
        outString[indexBorderXY(RandomArtMapWidth - 2,RandomArtMapHeight - 1)] = FirstAscii("+");
        
        
        for y in 0..<RandomArtHeight{
            for x in 0..<RandomArtWidth{
                let v = outString[indexXY(x , y)];
                if (v >= 0 && v < lenMax) {
                    outString[indexXY(x , y)] = Values[Int(v)];
                }else{
                    outString[indexXY(x , y)] = FirstAscii("!");
                }
            }
        }
        
        let titleLen = title != nil ? title!.count  : 0;
        if titleLen > 0{
            let   titleStart  = max((RandomArtWidth - titleLen)/2,0)
            
            var i = titleStart;
            var j =  0;
            while  i < RandomArtWidth && j  < titleLen {
                
                let idx = title!.index(title!.startIndex, offsetBy:j);
            outString[indexXY(i , -1)] = title![idx].asciiValue ?? FirstAscii(" ")
                i += 1
                j += 1
            }
            
        }
        
        let endLen = end != nil ? end!.count  : 0;
        if endLen > 0{
            let   endLenStart  = max((RandomArtWidth - endLen)/2,0)
            
            var i = endLenStart;
            var j =  0;
            while  i < RandomArtWidth && j  < endLen {
                
                let idx = end!.index(end!.startIndex, offsetBy:j);
            outString[indexXY(i , RandomArtHeight)] = end![idx].asciiValue ?? FirstAscii(" ")
                i += 1
                j += 1
            }
            
        }
        
    }
    
    static func test(){ 
    }
}
