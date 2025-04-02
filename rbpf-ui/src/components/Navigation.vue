<template>
  <v-navigation-drawer app>
    <v-list-item link>
      <v-list-item-content @click="goto('app')">
        <v-list-item-title class="text-h6">
          Rust eBPF Firewall
        </v-list-item-title>
      </v-list-item-content>
    </v-list-item>
    <v-divider></v-divider>

    <v-list dense nav>
      <!-- v-list-item-group управляет активным элементом -->
      <v-list-item-group v-model="activeItem" color="primary">
        <v-list-item
            v-for="(item, index) in navigation"
            :key="index"
            :value="item.path"
            link
            @click="goto(item.path)"
        >
          <v-list-item-icon>
            <v-icon>{{ item.icon }}</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title>{{ item.text }}</v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list-item-group>
    </v-list>
  </v-navigation-drawer>
</template>

<script lang="ts" setup>
import { ref, watchEffect } from "vue";
import { useRoute, useRouter } from "vue-router";

const router = useRouter();
const route = useRoute();

// Навигационные пункты
const navigation = [
  { text: "Правила", path: "/rules", icon: "mdi-shield-check" },
  { text: "Логи", path: "/logs", icon: "mdi-file-document-outline" },
];

// Переменная для активного пункта меню
const activeItem = ref(route.path);

// Функция для навигации
const goto = (path: string) => {
  router.push(path);
};

// Следим за изменением маршрута и обновляем активный пункт
watchEffect(() => {
  activeItem.value = route.path;
});
</script>

<style scoped></style>