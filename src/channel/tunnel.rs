/*
   主要实现加密信道两次交互数据处理
   包括以下：
   1 从mysql或者redis读取伪值唯一标识对应的私钥
     先从redis读，如果没有从mysql读，并回写到redis中
   2 生成TOKEN写入redis
       关联预值D
   3
*/

/*
    处理协商第一个请求
 */
pub(crate) fn tunnel_first(data: &Vec<u8>) {

}

/*
    处理协商第二个请求
 */
pub fn tunnel_second() {

}