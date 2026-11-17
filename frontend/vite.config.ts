import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({plugins:[vue()],build:{outDir:'dist',emptyOutDir:true,cssCodeSplit:false,rolldownOptions:{output:{codeSplitting:false,entryFileNames:'app.js',assetFileNames:'app.[ext]'}}}})
