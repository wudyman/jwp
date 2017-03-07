package javastd;

interface AInterface<K,V>{
	V fun1(K k,V v);
}

 class XClass implements AInterface<Object,Object>
{
	public Object fun1(Object o1,Object o2){
		System.out.println("this is XClass fun1");
		return o2;
	}
}