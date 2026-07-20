# 快速开始

## 环境要求

部署 V3il 前，请准备：

- Linux 主机、Docker Engine 和 Docker Compose；
- PostgreSQL；
- 五个兼容 OpenAI API 的模型端点，对应 `cso`、`cth`、`cde`、`cie` 和 `cir`；
- LightRAG 使用的 embedding 与 LLM 端点；
- 可供欺骗环境使用的 Docker 主机和网络；
- 可信管理网络与持久存储。

## 1. 创建配置

```bash
cp .v3il/config.json.example .v3il/config.json
```

编辑 `.v3il/config.json`，完成以下配置：

- 修改 JWT 签名密钥和初始管理员密码；
- 配置 PostgreSQL；
- 为五个智能体填写 API 地址、密钥和模型；
- 配置 LightRAG 的 embedding 与 LLM；
- 根据部署规模调整智能体运行、行为采集和自动化参数。

同时检查 Compose 中的 PostgreSQL 用户、密码和数据库名称，确保与应用配置一致。

## 2. 构建运行镜像

```bash
cd sandbox
./build.sh
cd ..
```

需要承载欺骗环境的 Managed Host 应提前准备相同镜像，或使用团队现有的镜像分发流程同步。

## 3. 启动平台

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

默认访问地址为 `http://127.0.0.1:8000`。

## 4. 准备基础设施

使用初始管理员登录后：

1. 在 Managed Hosts 中确认本地 Docker 主机，或添加远程主机；
2. 在 Sandbox Images 中注册刚刚构建的镜像；
3. 如需代理外联，在 Egress Proxies 中添加代理；
4. 检查主机、镜像和检测状态。

## 5. 创建第一个环境

进入 Deception Environments，填写环境名称、说明、Managed Host、Sandbox Image、外联策略和适配模式。可以附加参考 URL、代码、文档或压缩包。

创建后进入环境 Agent Console，描述：

- 环境对应的业务或系统背景；
- 需要呈现的服务、身份和数据；
- 期望观察的攻击路径；
- 关键交互和监测目标；
- 对内容真实性与诱导深度的要求。

Ph4ntom 完成设计、部署和验证后，环境进入运行状态。

## 6. 验证运营链路

从隔离的测试网络访问环境，确认：

- 攻击者可见服务符合设计；
- 行为和检测信号进入环境工作区；
- 相关活动形成 ThreatIncident；
- 智能体任务与证据开始更新；
- Incident 工作区能够查看时间线和分析；
- 报告与知识服务连接正常。

## 部署注意事项

V3il 需要访问 Docker 管理接口，并会处理模型凭据、基础设施凭据和攻击行为数据。请将 Web 控制台、API、PostgreSQL、Docker 管理网络和配置文件放在可信网络中。攻击者可见环境应位于独立网段，避免访问生产资产和管理端点。
