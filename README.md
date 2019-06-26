# android_frida_trace_myTrace
android使用frida脚本追踪方法调用，方法之间的关系一目了然。

### 开始
在 [android逆向__超级好用，使用frida追踪方法](https://juejin.im/post/5d0ca6c8e51d45777b1a3db2) 一文中，介绍了如何使用firda脚本追踪android的方法调用，在实际的使用中，方法被调用，就会在终端打印方法的开始标记、方法的参数和方法的结束标记。但是看起来有些凌乱：
```
*** entered com.test.flyer.MainActivity$1.onClick
arg[0]: android.support.v7.widget.AppCompatButton{4267c9c8 VFED..C. ...P.... 0,0-264,144 #7f070022 app:id/button}
*** entered com.test.flyer.MainActivity.test
arg[0]: Jack
*** entered com.test.flyer.MainActivity.gainAge
arg[0]: 16
retval: 26
*** exiting com.test.flyer.MainActivity.gainAge
*** entered com.test.flyer.MainActivity.gainEnjoy
arg[0]: 篮球
retval: 我喜欢篮球
*** exiting com.test.flyer.MainActivity.gainEnjoy
retval: OK
*** exiting com.test.flyer.MainActivity.test
retval: undefined
*** exiting com.test.flyer.MainActivity$1.onClick
```
截图效果：

![](https://user-gold-cdn.xitu.io/2019/6/26/16b9392baa6668e0?w=1246&h=1090&f=jpeg&s=167283)

### 改进
在这样一堆打印中，我们不能清晰的分辨各个方法的嵌套关系，总之一句话，就是不够醒目。于是乎对 raptor_frida_android_trace.js 脚本做了改进，下面是部分内容：
```
var logContentArray = new Array();

var singlePrefix = "|----"


// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	// slice() 方法可提取字符串的某个部分，并以新的字符串返回被提取的部分
	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {

		// hook方法
		hook[targetMethod].overloads[i].implementation = function() {

			var logContent_1 = "entered--"+targetClassMethod;

			var prefixStr = gainLogPrefix(logContentArray);

			logContentArray.push(prefixStr + logContent_1);

			console.warn(prefixStr + logContent_1);

			// print backtrace, 打印调用堆栈
			// Java.perform(function() {
			// 	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			// 	console.log(prefixStr +"Backtrace:" + bt);
			// });   

			// print args
			// if (arguments.length) console.log();

			// 打印参数
			for (var j = 0; j < arguments.length; j++) 
			{
				var tmpLogStr = prefixStr + "arg[" + j + "]: " + arguments[j];
				console.log(tmpLogStr);
				logContentArray.push(tmpLogStr);
			}
			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			// 打印返回值
			// console.log("\n"+ targetClassMethod +"--retval: " + retval);
			var tmpReturnStr = prefixStr + "retval: " + retval;
			logContentArray.push(tmpReturnStr);
			console.log(tmpReturnStr);
			//结束标志
			var logContent_ex = "exiting--" + targetClassMethod;
			logContentArray.push(prefixStr + logContent_ex);
			console.warn(prefixStr + logContent_ex);
			return retval;
		}
	}
}

// 获取打印前缀
function gainLogPrefix(theArray)
{
	var lastIndex = theArray.length - 1;

	if (lastIndex<0)
	{
		return singlePrefix;
	}
	
	for (var i = lastIndex; i >= 0; i--) 
	{
		var tmpLogContent = theArray[i];
		var cIndex = tmpLogContent.indexOf("entered--");

		if ( cIndex == -1)
		{
			var cIndex2 = tmpLogContent.indexOf("exiting--");
			if ( cIndex2 == -1)
			{
				continue;
			}
			else
			{
				//与上个方法平级
				var resultStr = tmpLogContent.slice(0,cIndex2);
				return resultStr;
			}
		}
		else
		{
			//在上个方法的内部
			var resultStr = singlePrefix + tmpLogContent.slice(0,cIndex);//replace(/entered--/, "");
			// console.log("("+tmpLogContent+")前缀是：("+resultStr+")");
			return resultStr;
			
		}
	}
	return "";
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		trace("com.test.flyer.MainActivity");
		// trace("com.test.flyer.MainActivity.gainAge");

		// trace("com.target.utils.CryptoUtils.decrypt");
		// trace("com.target.utils.CryptoUtils");
		// trace("CryptoUtils");
		// trace(/crypto/i);
		// trace("exports:*!open*");

	});   
}, 0);
```
js文件内，主要新增 gainLogPrefix方法和 gainLogPrefix_Module方法，用于生成"|----"标记。

使用新的js追踪方法，终端打印如下：
```
|----entered--com.test.flyer.MainActivity$1.onClick
|----arg[0]: android.support.v7.widget.AppCompatButton{426a5f40 VFED..C. ...P.... 0,0-264,144 #7f070022 app:id/button}
|----|----entered--com.test.flyer.MainActivity.test
|----|----arg[0]: Jack
|----|----|----entered--com.test.flyer.MainActivity.gainAge
|----|----|----arg[0]: 16
|----|----|----retval: 26
|----|----|----exiting--com.test.flyer.MainActivity.gainAge
|----|----|----entered--com.test.flyer.MainActivity.gainEnjoy
|----|----|----arg[0]: 篮球
|----|----|----retval: 我喜欢篮球
|----|----|----exiting--com.test.flyer.MainActivity.gainEnjoy
|----|----retval: OK
|----|----exiting--com.test.flyer.MainActivity.test
|----retval: undefined
|----exiting--com.test.flyer.MainActivity$1.onClick
```
截图效果：

![](https://user-gold-cdn.xitu.io/2019/6/26/16b938ca5fe26c74?w=1642&h=738&f=jpeg&s=240850)

看起来顺眼多了，哈哈哈，希望各位大佬能喜欢。

### 结束
本次测试项目和js脚本获取方式：

1、关注公众号"逆向APP"，回复"frida追踪方法02"
![](https://user-gold-cdn.xitu.io/2019/6/26/16b9397aa15a907a?w=258&h=258&f=jpeg&s=27708)

2、[github地址](https://github.com/luoyanbei/android_frida_trace_myTrace)，可以帮忙点个 Star
