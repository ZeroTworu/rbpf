<template>
  <v-container class="fill-height d-flex flex-column">
    <v-card-title>Правила фильтрации трафика</v-card-title>
    <v-btn color="primary" class="mb-4" @click="openDialog(null)">Добавить правило</v-btn>
    <v-data-table
        :headers="headers"
        :items="rules"
        class="elevation-1 flex-grow-1"
        density="comfortable"
    >
      <template v-slot:item.name="{ item }">
        <strong>{{ item.name }}</strong>
      </template>

      <template v-slot:item.source="{ item }">
        {{ formatIpPort(item.v4, item.v6, item.source_addr_v4, item.src_ip_high, item.src_ip_low, item.source_port_start, item.source_port_end) }}
      </template>

      <template v-slot:item.destination="{ item }">
        {{ formatIpPort(item.v4, item.v6, item.destination_addr_v4, item.dst_ip_high, item.dst_ip_low, item.destination_port_start, item.destination_port_end) }}
      </template>

      <template v-slot:item.protocol="{ item }">
        <v-chip :color="item.tcp ? 'blue' : 'green'">
          {{ item.tcp ? "TCP" : "UDP" }}
        </v-chip>
      </template>

      <template v-slot:item.action="{ item }">
        <v-icon :color="item.drop ? 'red' : 'green'">
          {{ item.drop ? 'mdi-close-circle' : 'mdi-check-circle' }}
        </v-icon>
      </template>

      <template v-slot:item.on="{ item }">
        <v-switch v-model="item.on" disabled></v-switch>
      </template>

      <template v-slot:item.edit="{ item }">
        <v-icon @click="openDialog(item)">mdi-pencil</v-icon>
      </template>
    </v-data-table>
    <RuleDialog v-model="dialog" :rule="editingRule" @save="saveRule" @close="dialog = false" />
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { useStore } from "vuex";
import RuleDialog from "@/components/RuleDialog.vue";

const store = useStore();
const dialog = ref(false);
const editingRule = ref(null);

const headers = [
  { title: "Имя правила", key: "name" },
  { title: "Источник", key: "source" },
  { title: "Назначение", key: "destination" },
  { title: "Протокол", key: "protocol" },
  { title: "Действие", key: "action" },
  { title: "Активно", key: "on" },
  { title: "", key: "edit" },
];

const formatIpPort = (v4: boolean, v6: boolean, ipv4: number, high: number, low: number, startPort: number, endPort: number) => {
  const ip = v4 ? formatIpV4(ipv4) : v6 ? formatIpV6(high, low) : "-";
  return startPort === endPort ? `${ip}` : `${ip}:${startPort}-${endPort}`;
};

const formatIpV4 = (ip: number) => {
  return `${(ip >> 24) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 8) & 0xFF}.${ip & 0xFF}`;
};

const formatIpV6 = (high: number, low: number) => {
  return `${(high >>> 16).toString(16)}:${(high & 0xFFFF).toString(16)}:${(low >>> 16).toString(16)}:${(low & 0xFFFF).toString(16)}`;
};

const rules = computed(() => store.getters["rules/rules"]);

const openDialog = (rule) => {
  console.log("openDialog", rule);
  editingRule.value = rule ? { ...rule } : { name: "", on: false };
  dialog.value = true;
};

const saveRule = (rule) => {
  if (editingRule.value) {
    store.dispatch("rules/updateRule", rule);
  } else {
    store.dispatch("rules/addRule", rule);
  }
  dialog.value = false;
};

onMounted(() => {
  store.dispatch("rules/fetchRules");
});
</script>
