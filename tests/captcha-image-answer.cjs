// Test-only image reader: solve the displayed sum as the browser user would.
// This adds no answer endpoint, token decoder or verification bypass to the app.
const {inflateSync} = require('node:zlib');
const digits = {
    1:['00100','01100','00100','00100','00100','00100','01110'],
    2:['01110','10001','00001','00010','00100','01000','11111'],
    3:['11110','00001','00001','01110','00001','00001','11110'],
    4:['00010','00110','01010','10010','11111','00010','00010'],
    5:['11111','10000','10000','11110','00001','00001','11110'],
    6:['01110','10000','10000','11110','10001','10001','01110'],
    7:['11111','00001','00010','00100','01000','01000','01000'],
    8:['01110','10001','10001','01110','10001','10001','01110'],
    9:['01110','10001','10001','01111','00001','00001','01110']
};
module.exports = function imageAnswer(dataUrl) {
    const png = Buffer.from(dataUrl.split(',')[1], 'base64'), chunks = [];
    const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
    if (png[24] !== 8 || png[25] !== 2) throw Error('Test reader expects an RGB question image');
    for (let offset=8; offset<png.length;) {
        const size=png.readUInt32BE(offset), kind=png.toString('ascii',offset+4,offset+8);
        if (kind==='IDAT') chunks.push(png.subarray(offset+8,offset+8+size));
        offset += size+12;
    }
    const raw=inflateSync(Buffer.concat(chunks)), stride=1+width*3;
    const ink=(x,y)=>{const p=y*stride+1+x*3;return raw[p]===40&&raw[p+1]===62&&raw[p+2]===100;};
    const rows=Array.from({length:height},(_,y)=>y).filter(y=>Array.from({length:width},(_,x)=>x).some(x=>ink(x,y)));
    const scale=(rows.at(-1)-rows[0]+1)/7, groups=[];
    for(let x=0;x<width;x++) {
        if (!rows.some(y=>ink(x,y))) continue;
        if (!groups.length || x>groups.at(-1).at(-1)+1) groups.push([]);
        groups.at(-1).push(x);
    }
    const read=group=>{
        const pattern=Array.from({length:7},(_,y)=>Array.from({length:group.length/scale},(_,x)=>ink(group[0]+x*scale,rows[0]+y*scale)?'1':'0').join(''));
        for(const [digit,font] of Object.entries(digits)) {
            const used=[0,1,2,3,4].filter(x=>font.some(row=>row[x]==='1'));
            if(font.map(row=>row.slice(used[0],used.at(-1)+1)).join('/')===pattern.join('/')) return Number(digit);
        }
        throw Error('Could not read question digit');
    };
    return String(read(groups[0])+read(groups[2]));
};
