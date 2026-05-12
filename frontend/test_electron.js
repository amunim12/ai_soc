const e = require('electron');
const fs = require('fs');
fs.writeFileSync('C:/Temp/electron_result.txt', 
  'type:' + typeof e + '\nvalue:' + (typeof e === 'string' ? e : JSON.stringify(Object.keys(e || {}).slice(0,5))) + '\npid:' + process.pid + '\nelectron:' + (process.versions.electron||'none')
);
