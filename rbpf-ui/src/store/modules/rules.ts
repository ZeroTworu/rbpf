import { Module } from "vuex";
import type { RootState }  from "@/store";
import { Api } from "@/api/rulesApi";

export enum TrafficType {
    Input = 0,
    Output = 1,
}

export enum ProtocolVersionType {
    V4 = 0,
    V6 = 1,
}

export enum ProtocolType {
    TCP = 0,
    UDP = 1,
}

export interface Rule {
    rule_id: number;
    name: string;
    source_addr_v4: number;
    source_mask_v4: number;
    source_mask_v6: number;
    destination_addr_v4: number;
    destination_mask_v4: number;
    destination_mask_v6: number;
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
    ifindex: number;
    v6: boolean;
    v4: boolean;
    uindex: number;
    from_db: boolean;
}

function withDefaults(rule: Partial<Rule>): Rule {
    return {
        rule_id: 0,
        name: '',
        source_addr_v4: 0,
        source_mask_v4: 0,
        source_mask_v6: 0,
        destination_addr_v4: 0,
        destination_mask_v4: 0,
        destination_mask_v6: 0,
        source_port_start: 0,
        source_port_end: 0,
        destination_port_start: 0,
        destination_port_end: 0,
        dst_ip_high: 0,
        dst_ip_low: 0,
        src_ip_high: 0,
        src_ip_low: 0,
        tcp: false,
        udp: false,
        drop: false,
        ok: false,
        on: false,
        input: false,
        output: false,
        ifindex: 0,
        uindex: 0,
        v6: false,
        v4: false,
        from_db: true,
        ...rule,
    };
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
            const response = await Api.createRule(withDefaults(rule));
            commit("SET_RULES", response.data);
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
            await Api.updateRule(rule);
            commit("SET_RULES", rule);
        } catch (error) {
            console.error("Ошибка при создании правила", error);
        }
    },
    async removeRule({ commit }, ruleId: number) {
        try {
            await Api.deleteRule(ruleId);
            commit("SET_RULES", ruleId);
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
