<%@ page language="java" contentType="text/html; charset=utf-8"
    pageEncoding="utf-8"%>
<%@ page import="java.io.*,java.util.*" %>
    <%  
    //设置输出信息的格式及字符集  
    /*
    response.setContentType("text/xml; charset=UTF-8");  
    response.setHeader("Cache-Control","no-cache");  
    out.println("<response>");  
      
    for(int i=0;i<2;i++){  
    out.println("<name>"+(int)(Math.random()*10)+  
       "号传感器</name>");  
    out.println("<count>" +(int)(Math.random()*100)+ "</count>");  
    }  
    out.println("</response>");  
    out.close();  
    */
    %>   
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>get text</title>
</head>
<body>
<!-- 
<h2>HTTP 头部请求实例</h2>
<table width="100%" border="1" align="center">
<tr bgcolor="#949494">
<th>Header Name</th><th>Header Value(s)</th>
</tr>
 
<%
   Enumeration headerNames = request.getHeaderNames();
   while(headerNames.hasMoreElements()) {
      String paramName = (String)headerNames.nextElement();
      out.print("<tr><td>" + paramName + "</td>\n");
      String paramValue = request.getHeader(paramName);
      out.println("<td> " + paramValue + "</td></tr>\n");
   }
%>
</table>
-->
<!-- <%= request.getParameter("tt")%>-->
<%
// 解决中文乱码的问题
String text = new String((request.getParameter("tt")).getBytes("ISO-8859-1"),"UTF-8");
%>
<%=text%>
<form id="convert" method="post" action="convert_text">
<input type="text" name="tt" value="<%=text%>"/>
<input type="submit" value="提交" />
</form>   
</body>
</html>