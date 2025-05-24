# IDA-AI ComprehendAI 2.0
对ComprehendAI的二次开发调试  
源项目地址：https://github.com/Kvancy/ComprehendAI  
这里使用的是阿里的百炼大模型，因为免费，但是病毒分析会触发阿里账号封禁，客服不给解封只会对不起。  
![image](https://github.com/user-attachments/assets/4eaa65b9-cb32-48ac-b20b-c8ccc1e1f3d8)

原本默认的分析深度最大是2，经测试将深度调整为15后并没有深入的分析  
故将代码进行调试  
![image](https://github.com/user-attachments/assets/0572d8d2-e0e5-492e-9294-14d452f84ec3)

原本的只会分析函数，对函数进行分析，并不会分析引用的全局变量  
故将此功能加入  
![image](https://github.com/user-attachments/assets/5c98869d-7662-44f7-884a-f0f18328c9f6)

这里优化了相关的提示词  
![image](https://github.com/user-attachments/assets/2e733d07-eb47-4c55-8911-fc287c5ab039)

其他细节变化不做描述  
函数及深度分析  
![image](https://github.com/user-attachments/assets/fa49a116-6de2-4824-931b-e73a32140715)
![image](https://github.com/user-attachments/assets/5ac01907-e9ca-49bb-8543-2816d1ff4919)

默认深度分析为15  
![image](https://github.com/user-attachments/assets/3d3f3d54-f34d-4111-b718-27717398fde3)

询问功能  
![image](https://github.com/user-attachments/assets/c780d117-2557-40d5-874c-8b5ceb438244)





