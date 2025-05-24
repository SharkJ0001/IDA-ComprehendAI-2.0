# IDA-AI ComprehendAI 2.0
对ComprehendAI的二次开发调试
环境：IDA 9.1，python3.13  
需要将pip install openai进行安装 
源项目地址：https://github.com/Kvancy/ComprehendAI  
 
并且下载的两个文件要放在IDApro91\plugins插件目录下  
![image](https://github.com/user-attachments/assets/2b455f95-82be-49a6-b0b9-d550eec3cd94)

这里使用的是阿里的百炼大模型，因为免费，但是病毒分析会触发阿里账号封禁，客服不给解封只会对不起，使用的时候自己注意吧。  
![image](https://github.com/user-attachments/assets/4eaa65b9-cb32-48ac-b20b-c8ccc1e1f3d8)

原本默认的分析深度最大是2，经测试将深度调整为15后并没有深入的分析  
故将代码进行调试  
![image](https://github.com/user-attachments/assets/0572d8d2-e0e5-492e-9294-14d452f84ec3)

原本的只会分析函数，对函数进行分析，并不会分析引用的全局变量，故加入全局变量分析功能  
![image](https://github.com/user-attachments/assets/5c98869d-7662-44f7-884a-f0f18328c9f6)

根据自己的需求，重写相关提示词  
![image](https://github.com/user-attachments/assets/2e733d07-eb47-4c55-8911-fc287c5ab039)

其他细节变化不做描述  
函数及深度分析正常使用  
![image](https://github.com/user-attachments/assets/fa49a116-6de2-4824-931b-e73a32140715)
![image](https://github.com/user-attachments/assets/5ac01907-e9ca-49bb-8543-2816d1ff4919)

默认深度分析为15自己根据需求调整就行了  
![image](https://github.com/user-attachments/assets/92039ab7-7739-4c92-b0f7-de3c64d548db)


询问功能分为两种，一种是结合代码，一种是直接提问，都能正常使用  
![image](https://github.com/user-attachments/assets/5e86f596-c2b1-4acc-86b5-f429a0cdd029)






