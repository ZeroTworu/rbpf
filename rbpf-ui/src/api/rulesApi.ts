import axios from "axios";

export class Api {
    static getRules() {
        return axios.get("/api/v1/rules");
    }
    static updateRule(val) {
        return axios.put(`/api/v1/rules/${val.rule_id}`, val);
    }

    static createRule(val) {
        return axios.post("/api/v1/rules", val);
    }

    static deleteRule(id) {
        return axios.delete(`/api/v1/rules/${id}`);
    }
}