<script setup lang="ts">
import {computed} from 'vue'
import {NConfigProvider,NMessageProvider,NDialogProvider,darkTheme,zhCN,dateZhCN} from 'naive-ui'
import type {GlobalThemeOverrides} from 'naive-ui'
import {dark} from './store'
import ConsoleApp from './components/ConsoleApp.vue'
function createOverrides(isDark:boolean):GlobalThemeOverrides{return {
 common:{
  primaryColor:isDark?'#639adc':'#356fb3',primaryColorHover:isDark?'#80afe7':'#4783c7',primaryColorPressed:isDark?'#4f85c5':'#285b98',
  successColor:isDark?'#66b69d':'#23836b',infoColor:isDark?'#88a7cc':'#4c729c',warningColor:isDark?'#d3ab69':'#9e742e',errorColor:isDark?'#de8585':'#b94a48',
  borderRadius:'7px',fontFamily:'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif',fontSize:'14px',
  bodyColor:isDark?'#080d12':'#f3f6fa',cardColor:isDark?'#0b1016':'#ffffff',modalColor:isDark?'#0b1016':'#ffffff',tableColor:isDark?'#0b1016':'#ffffff',
  textColorBase:isDark?'#eef1f5':'#253347',textColor1:isDark?'#eef1f5':'#253347',textColor2:isDark?'#c5cbd3':'#44556b',textColor3:isDark?'#9ea7b3':'#62738a',
  borderColor:isDark?'#262f39':'#dfe6ee',inputColor:isDark?'#101720':'#f7f9fc',actionColor:isDark?'#0f161f':'#f7f9fc'
 },
 DataTable:{
  thColor:isDark?'#0f161f':'#f7f9fc',thColorHover:isDark?'#192535':'#edf3fa',thColorSorting:isDark?'#142131':'#eef4fb',
  tdColor:isDark?'#0b1016':'#ffffff',tdColorHover:isDark?'#142131':'#eff5fc',tdColorSorting:isDark?'#0d131b':'#fbfcfe',
  thPaddingSmall:'10px 10px',tdPaddingSmall:'7px 10px',fontSizeSmall:'14px',borderColor:isDark?'#262f39':'#e6ecf3'
 },Button:{fontWeight:'500'},Card:{paddingMedium:'24px'}
}}
const lightOverrides=createOverrides(false),darkOverrides=createOverrides(true)
const overrides=computed(()=>dark.value?darkOverrides:lightOverrides)
</script>
<template><NConfigProvider :theme="dark?darkTheme:null" :theme-overrides="overrides" inline-theme-disabled :locale="zhCN" :date-locale="dateZhCN"><NMessageProvider><NDialogProvider><ConsoleApp/></NDialogProvider></NMessageProvider></NConfigProvider></template>
