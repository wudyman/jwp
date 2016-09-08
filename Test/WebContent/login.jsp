<%@ page language="java" import="java.util.*" contentType="text/html; charset=utf-8"
    pageEncoding="utf-8"%>
<%
String path = request.getContextPath();
String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<base href="<%=basePath%>">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="cache-control" content="no-cache">
<meta http-equiv="expires" content="0">    
<meta http-equiv="keywords" content="keyword1,keyword2,keyword3">
<meta http-equiv="description" content="This is my page">
<title>login test</title>
</head>
<body>
<!--故事就是从这里开始的，这个表单召唤了login这个action,
带着username和password两个参数的request对象便飞了过去-->
<form id="loginId" method="post" action="login">
用户名：<input type="text" name="username" />
<br/>
密&nbsp;&nbsp;&nbsp;&nbsp;码：<input type="password" name="password" />
<br/>
<input type="submit" value="登录" />
</form>
</body>
</html>