/*
 * raptor_frida_android_trace.js - Code tracer for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script to trace arbitrary Java Methods and
 * Module functions for debugging and reverse engineering.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to @inode-, @federicodotta, @leonjza, and
 * @dankluev.
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_android_trace.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

//公众号：逆向APP

var logContentArray = new Array();

var singlePrefix = "|----"

// generic trace
function trace(pattern)
{
	// indexOf() 方法可返回某个指定的字符串值在字符串中首次出现的位置,未出现则返回-1
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

	if (type === "module") {
		console.log("is--module")
		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			traceModule(target.address, target.name);
		});

	} else if (type === "java") {
		console.log("is--java")

		// trace Java Class, 遍历加载的类，判断追踪的是否是类
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				// console.log("is--java--1--"+aClass.toString())

				if (aClass.match(pattern)) {

					console.log("is--java--2--"+aClass.toString())

					found = true;
					//match() 方法可在字符串内检索指定的值，或找到一个或多个正则表达式的匹配。
					// 该方法类似 indexOf() 和 lastIndexOf()，但是它返回指定的值，而不是字符串的位置。
					var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");

					console.log('('+aClass.toString()+')-----'+className.toString());

					traceClass(className);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method， 追踪方法
		if (!found) {
			try {
				console.log('trace---method---'+pattern.toString())
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
	}
}

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



// 获取打印前缀
function gainLogPrefix_Module(theArray,status)
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
			if (tmpLogContent.indexOf(status)==-1)
			{
				//与上一条输出 平级
				var resultStr = tmpLogContent.slice(0,cIndex);//replace(/entered--/, "");
				// console.log("("+tmpLogContent+")前缀是：("+resultStr+")");
				return resultStr;
			}
			else
			{
				//在上个方法的内部
				var resultStr = singlePrefix + tmpLogContent.slice(0,cIndex);//replace(/entered--/, "");
				// console.log("("+tmpLogContent+")前缀是：("+resultStr+")");
				return resultStr;
			}
			
		}
	}


	return "";

}

// trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {


		onEnter: function(args) {


			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
			this.flag = true;

			if (this.flag) {
				var prefixStr = gainLogPrefix_Module(logContentArray,"entered--");
				// console.warn("\n*** entered " + name);

				var logContent_1 = "entered--"+name;
				logContentArray.push(prefixStr + logContent_1);
				console.warn(prefixStr + logContent_1);

				// print backtrace， 打印调用堆栈
				// console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {


			if (this.flag) {

				var prefixStr = gainLogPrefix_Module(logContentArray,"non6soidjs3kejf6sle8ifsjie");

				// print retval
				// console.log("\nretval: " + retval);
				var logContent_1 = "retval:"+retval;
				logContentArray.push(prefixStr + logContent_1);
				console.warn(prefixStr + logContent_1);

				var logContent_2 = "exiting--"+name;
				logContentArray.push(prefixStr + logContent_2);
				console.warn(prefixStr + logContent_2);


				// console.warn("\n*** exiting " + name);
			}
		}

	});
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
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
