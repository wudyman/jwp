<%@ page language="java" contentType="text/html; charset=utf-8"
    pageEncoding="utf-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Hello World</title>
</head>
<body>
<%
out.println("hello!!!");
%>
<jsp:useBean id="date" class="java.util.Date" /> 
<p>日期为：<%= date %>

<jsp:useBean id="students1" 
                    class="javabean.StudentBean"> 
   <jsp:setProperty name="students1" property="name" 
                    value="王"/>
   <jsp:setProperty name="students1" property="age"
                    value="10"/>
</jsp:useBean>

<p>学生名字: 
   <jsp:getProperty name="students1" property="name"/>
</p>
<p>学生年龄: 
   <jsp:getProperty name="students1" property="age"/>
</p>


</body>
</html>