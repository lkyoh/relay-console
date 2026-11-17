import {copyFile} from 'node:fs/promises'
for(const name of ['index.html','app.js','app.css']) await copyFile(new URL('./dist/'+name,import.meta.url),new URL('../'+name,import.meta.url))
console.log('Runtime assets synchronized. Run python3 build_installer.py from the repository root to rebuild the portable installer.')
