import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
 import App from "./App.vue";
 // 路由懒加载：按需加载各视图，减小首屏体积
 const TasksView = () => import("./views/TasksView.vue");
 const CreateView = () => import("./views/CreateView.vue");
 const BoardView = () => import("./views/BoardView.vue");
 const SettingsView = () => import("./views/SettingsView.vue");
 const HardTargetsView = () => import("./views/HardTargetsView.vue");
 const IntelView = () => import("./views/IntelView.vue");
 const KnowledgeView = () => import("./views/KnowledgeView.vue");
 const VulnsView = () => import("./views/VulnsView.vue");
 const RuntimeLogsView = () => import("./views/RuntimeLogsView.vue");
 import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import "./style.css";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", component: TasksView },
    { path: "/create", component: CreateView },
    { path: "/hard-targets", component: HardTargetsView },
    { path: "/intel", component: IntelView },
    { path: "/knowledge", component: KnowledgeView },
    { path: "/vulns", component: VulnsView },
    { path: "/runtime-logs", component: RuntimeLogsView },
    { path: "/settings", component: SettingsView },
    { path: "/task/:id", component: BoardView, props: true },
  ],
});

router.beforeEach(async (to) => {
  if (!authReadyRef.value) await loadAuthRole();
  if (authRoleRef.value === "observer" && ["/create", "/settings", "/intel", "/knowledge", "/vulns", "/runtime-logs"].includes(to.path)) {
    return "/";
  }
  return true;
});

createApp(App).use(router).mount("#app");
