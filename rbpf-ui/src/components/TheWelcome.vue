<template>
  <div class="zero-two-svg" v-html="svgContent" />
</template>

<script setup>
const svgContent = `
<svg viewBox="0 0 512 512" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
  <!-- Zero Two silhouette (simplified for flat illustration style) -->
  <g fill="#ff6b81">
    <path d="M256 32c-44 0-80 36-80 80v40c0 24 16 40 40 40v40h80v-40c24 0 40-16 40-40v-40c0-44-36-80-80-80z"/>
    <circle cx="256" cy="120" r="16" fill="#fff"/>
    <!-- Horns -->
    <path d="M236 30c-8 10-12 24-10 34l10-4c-2-6 0-16 4-24l-4-6z"/>
    <path d="M276 30c8 10 12 24 10 34l-10-4c2-6 0-16-4-24l4-6z"/>
  </g>

  <!-- Shield icon (mdi-shield-check) -->
  <path fill="#e53935" d="M12 128L256 16l244 112v120c0 130.9-95.1 247.6-244 248-148.9-.4-244-117.1-244-248V128zm340.6 84.6l-100 100c-4.7 4.7-12.3 4.7-17 0l-52-52c-4.7-4.7-4.7-12.3 0-17s12.3-4.7 17 0l43.5 43.5 91.5-91.5c4.7-4.7 12.3-4.7 17 0s4.7 12.3 0 17z" transform="translate(120, 180) scale(0.5)"/>
</svg>
`;
</script>

<style scoped>
.zero-two-svg {
  width: 300px;
  height: auto;
}
</style>
