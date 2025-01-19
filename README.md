# 如何使用？
使用apatch管理器加载kpm模块后，在控制中输入将要ptrace注入的app的uid即可。
同一时间只能对一个app起作用，更换app注入需要在控制中重新输入目标app的uid。

# 注意事项
目前仅在少数机型上通过测试，可能存在不兼容的情况。
只处理了/proc/pid/status以及/proc/pid/stat这两个文件的ptrace特征。
模块会强制让app自身的ptrace相关操作失败可能会导致部分app无法打开。