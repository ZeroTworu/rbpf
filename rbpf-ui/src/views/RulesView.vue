<template>
  <v-container class="fill-height d-flex flex-column">
    <v-card-title>Правила фильтрации трафика</v-card-title>
    <v-btn color="primary" class="mb-4" @click="openDialog(null)">Добавить правило</v-btn>
    <v-data-table
        :headers="headers"
        :items="rules"
        :sort-by="[{ key: 'order', order: 'asc' }]"
        class="elevation-1 flex-grow-1"
        density="comfortable"
    >
      <template v-slot:item="{ item }">
        <RuleRow :rule="item" @edit="openDialog" @switch-on="switchOn" @switch-drop="switchDrop"/>
      </template>
    </v-data-table>
    <RuleDialog v-model="dialog" :rule="editingRule" @save="saveRule" @close="dialog = false" />
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { useStore } from "vuex";
import RuleDialog from "@/components/RuleDialog.vue";
import RuleRow from "@/components/RuleRow.vue";

const store = useStore();
const dialog = ref(false);
const editingRule = ref(null);

const headers = [
  { title: "Имя правила", key: "name" },
  { title: "Источник", key: "source" },
  { title: "Назначение", key: "destination" },
  { title: "Протокол", key: "protocol" },
  { title: "Версия", key: "version" },
  { title: "Тип траффика", key: "traffic_type" },
  { title: "Действие", key: "action" },
  { title: "Активно", key: "on" },
  { title: "", key: "edit" },
];


const rules = computed(() => {
  const rules =  store.getters["rules/rules"];
  return rules.sort((a, b) => a.rule_id - b.rule_id);
});


const openDialog = (rule) => {
  console.log("openDialog", rule);
  editingRule.value = rule ? { ...rule } : { name: "", on: false };
  dialog.value = true;
};

const saveRule = (rule) => {
  if (editingRule.value.rule_id) {
    store.dispatch("rules/updateRule", rule);
  } else {
    store.dispatch("rules/addRule", rule);
  }
  dialog.value = false;
};

const switchOn = (rule) => {
  rule.on = !rule.on;
  store.dispatch("rules/updateRule", rule);
};

const switchDrop = (rule) => {
  rule.drop = !rule.drop;
  rule.ok = !rule.ok;
  store.dispatch("rules/updateRule", rule);
};

onMounted(() => {
  store.dispatch("rules/fetchRules");
});
</script>

<style scoped>

</style>
