create database if not exists stserver default charset utf8 collate utf8_general_ci;

/* 测试表 */
create table test(id int not null, name varchar(20) not null) default charset utf8;

/* 项目详细信息表 */
create table app(
    id int unsigned auto_increment primary key,
    name varchar(50) not null,
    description varchar(1000),
    certs blob -- 存储多证书keystore
) default charset utf8;

/* 
    项目关联客户端私钥管理 
    client_type 0 ios;1 android;2 harmony
*/
create table app_client_key(
    app_id int not null,
    client_type int not null,
    serialid varchar(100), -- 唯一标识
    pubkey varchar(2000), -- 公钥
    prikey varchar(2000), -- 私钥
    primary key (app_id, client_type, serialid)
) default charset utf8;

/* 网关接口 */
create table gateway_api (
    app_id int,
    api_name varchar(200) not null,
    hosts varchar(1000) not null, -- 主机间使用;间隔
    req_path varchar(255) not null,
    req_method varchar(5) default 'POST',
    threshold_sec int default 0, -- 默认值0表示不限制
    data_req_example varchar(2000),
    data_resp_example varchar(2000),
    use_state int default 1, -- 1 enable/0 disable
    load_balance int default 0, -- 负载策略 0轮询/1IP-Hash/2随机
    primary key (app_id, api_name)
) default charset utf8;

