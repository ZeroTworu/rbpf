import { Module } from "vuex";
import type { RootState }  from "@/store";
import { Api } from "@/api/rulesApi";

export interface Rule {
    rule_id: number;
    name: string;
    source_addr_v4: number;
    source_mask_v4: number;
    destination_addr_v4: number;
    destination_mask_v4: number;
    source_port_start: number;
    source_port_end: number;
    destination_port_start: number;
    destination_port_end: number;
    dst_ip_high: number;
    dst_ip_low: number;
    src_ip_high: number;
    src_ip_low: number;
    tcp: boolean;
    udp: boolean;
    drop: boolean;
    ok: boolean;
    on: boolean;
    input: boolean;
    output: boolean;
}

export interface RulesState {
    rules: Array<Rule>;
}

const state: RulesState = {
    rules: [],
};

const mutations = {
    SET_RULES(state: RulesState, rules: Array<Rule>) {
        state.rules = rules;
    },
    ADD_RULE(state: RulesState, rule: Rule) {
        state.rules = [ ...state.rules, rule ];
    },
    UPDATE_RULE(state: RulesState, updatedRule: Rule) {
        state.rules = state.rules.map(rule =>
            rule.rule_id === updatedRule.rule_id ? updatedRule : rule
        );
    },
    DELETE_RULE(state: RulesState, ruleId: number) {
        state.rules = state.rules.filter(rule => rule.rule_id !== ruleId);
    },
};

const actions = {
    async fetchRules({ commit }) {
        try {
            const response = await Api.getRules();
            commit("SET_RULES", response.data);
        } catch (error) {
            console.error("Ошибка при загрузке правил", error);
        }
    },
    async addRule({ commit }, rule: Rule) {
        try {
            console.log("ADD", rule);
            const response = await Api.createRule(rule);
            commit("ADD_RULE", response.data);
        } catch (error) {
            console.error("Ошибка при добавлении правила", error);
        }
    },
    async updateRule({ commit }, rule: Rule) {
        try {
            console.log("UPDATE", rule);
            const res = await Api.updateRule(rule);
            commit("SET_RULES", res.data);
        } catch (error) {
            console.error("Ошибка при обновлении правила", error);
        }
    },
    async createRule({ commit }, rule: Rule) {
        try {
            console.log("CREATE", rule);
            await Api.updateRule(rule);
            commit("CREATE_RULE", rule);
        } catch (error) {
            console.error("Ошибка при создании правила", error);
        }
    },
    async removeRule({ commit }, ruleId: number) {
        try {
            await Api.deleteRule(ruleId);
            commit("REMOVE_RULE", ruleId);
        } catch (error) {
            console.error("Ошибка при удалении правила", error);
        }
    },
};

const getters = {
    rules: (state: RulesState) => state.rules,
};

export const rules: Module<RulesState, RootState> = {
    namespaced: true,
    state,
    mutations,
    actions,
    getters,
};
