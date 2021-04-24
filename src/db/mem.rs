/*
   实现数据管理接口
   负责从redis读取数据，如果redis读取不到则从mysql读取数据，然后再将数据写入redis
   写数据时：
   1 仅redis，直接写入redis
   2 redis和mysql，先写入mysql再写入redis
   3 仅mysql，直接写入mysql
*/
