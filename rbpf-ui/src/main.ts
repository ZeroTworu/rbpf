import { createApp } from 'vue'

// Vuetify
import 'vuetify/styles'
import { createVuetify } from 'vuetify'
import '@mdi/font/css/materialdesignicons.css';
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import axios from "axios";
import router from "./router";
import store from "./store";
// Components
import App from './App.vue'

const vuetify = createVuetify({
    components,
    directives,
    icons: {
        defaultSet: 'mdi',
    },
})

axios.defaults.baseURL = 'http://localhost:8080';
const app = createApp(App);

app.use(vuetify);
app.use(store);
app.use(router);
app.mount("#app");
