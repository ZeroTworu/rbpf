<template>
  <v-dialog v-model="ipModalVisible" max-width="500px">
    <v-card>
      <v-card-title>Редактировать IP</v-card-title>
      <v-card-text>
        <v-checkbox v-model="editV4" label="IPv4" @change="toggleIpInput('v4')"></v-checkbox>
        <v-text-field v-model="ipV4" :disabled="!editV4" label="IPv4 адрес"></v-text-field>

        <v-checkbox v-model="editV6" label="IPv6" @change="toggleIpInput('v6')"></v-checkbox>
        <v-text-field v-model="ipV6" :disabled="!editV6" label="IPv6 адрес"></v-text-field>
      </v-card-text>
      <v-card-actions>
        <v-btn color="primary" @click="saveIpChanges">OK</v-btn>
        <v-btn color="secondary" @click="ipModalVisible = false">Отмена</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import {ref} from "vue";

const props = defineProps({ rule: Object });

const ipModalVisible = ref(false);
const ipV4 = ref('');
const ipV6 = ref('');
const editV4 = ref(false);
const editV6 = ref(false);

const openIpModal = (type: string) => {
  ipV4.value = formatIpV4(props.rule[`${type}_addr_v4`], props.rule[`${type}_mask_v4`]);
  ipV6.value = formatIpPort(props.rule, type === 'source');
  editV4.value = props.rule.v4;
  editV6.value = props.rule.v6;
  ipModalVisible.value = true;
};

const toggleIpInput = (type: string) => {
  if (type === 'v4') editV4.value = !editV4.value;
  if (type === 'v6') editV6.value = !editV6.value;
};

const saveIpChanges = () => {
  props.rule.v4 = editV4.value;
  props.rule.v6 = editV6.value;

  store.dispatch('rules/updateRule', props.rule);
  ipModalVisible.value = false;
};

</script>

<style scoped>

</style>