%module(directors="1") NabtoClient
%include <std_string.i>
%include <std_shared_ptr.i>
%include <std_except.i>
%include "stdint.i"
%shared_ptr(nabto::client::Context);
%shared_ptr(nabto::client::Connection);
%shared_ptr(nabto::client::Stream);
%shared_ptr(nabto::client::Coap);
%shared_ptr(nabto::client::FutureCallback);
%shared_ptr(nabto::client::CallbackFunction);
%shared_ptr(nabto::client::Logger);
%shared_ptr(nabto::client::Future);
%shared_ptr(nabto::client::FutureVoid);
%shared_ptr(nabto::client::FutureBuffer);
%shared_ptr(nabto::client::FutureMdnsResult);
%shared_ptr(nabto::client::FutureConnectionEvent);
%shared_ptr(nabto::client::MdnsResult);
%shared_ptr(nabto::client::MdnsResolver);
%shared_ptr(nabto::client::TcpTunnel);
%shared_ptr(nabto::client::ConnectionEventsListener);
%shared_ptr(nabto::client::ConnectionEventsCallback);

 //%ignore nabto::client::CallbackFunction;
 //%ignore nabto::client::CallbackFunction(std::function<void (Status status)> cb);

%{
    // put c/c++ code here
    #include "nabto_client.hpp"
%}


%feature("director") nabto::client::VoidCallback;
%feature("director") nabto::client::Logger;
%feature("director") nabto::client::FutureCallback;
%feature("director") nabto::client::ConnectionEventsCallback;

#ifdef SWIGJAVA

%typemap(jtype) std::vector<uint8_t> "byte[]"
%typemap(jstype) std::vector<uint8_t> "byte[]"
%typemap(jni) std::vector<uint8_t> "jbyteArray"
%typemap(javain) std::vector<uint8_t> "$javainput"

%typemap(jtype) std::vector<uint8_t>& "byte[]"
%typemap(jstype) std::vector<uint8_t>& "byte[]"
%typemap(jni) std::vector<uint8_t>& "jbyteArray"
%typemap(javain) std::vector<uint8_t>& "$javainput"


%typemap(in,numinputs=1) std::vector<uint8_t> buffer {
	unsigned char* data = (unsigned char*)JCALL2(GetByteArrayElements, jenv, $input, NULL);
	size_t dataLength = JCALL1(GetArrayLength, jenv, $input);
    $1 = std::vector<uint8_t>(data, data+dataLength);
}

%typemap(in,numinputs=1,noblock=1) std::vector<uint8_t>& {
	unsigned char* data = (unsigned char*)JCALL2(GetByteArrayElements, jenv, $input, NULL);
	size_t dataLength = JCALL1(GetArrayLength, jenv, $input);
    $*1_ltype $1_vec(data, data+dataLength);
    $1 = &$1_vec;
}

/* %typemap(in,numinputs=1) std::vector<uint8_t> buffer { */
/* 	unsigned char* data = (unsigned char*)JCALL2(GetByteArrayElements, jenv, $input, NULL); */
/* 	size_t dataLength = JCALL1(GetArrayLength, jenv, $input); */
/*     $1 = std::vector<uint8_t>(data, data+dataLength); */
/* } */


%typemap(javaout) std::vector<uint8_t> {
    return $jnicall;
 }
%typemap(javaout) std::vector<uint8_t>& {
    return $jnicall;
 }

%typemap(out) std::vector<uint8_t> {
   jbyteArray arr = JCALL1(NewByteArray, jenv, $1.size());
   JCALL4(SetByteArrayRegion, jenv, arr, 0, $1.size(), (const signed char*)$1.data());

   $result = arr;
}

#endif

#ifdef SWIGPYTHON
%typemap(in) std::vector<uint8_t> {
    Py_ssize_t len;
    char* buffer;
    PyBytes_AsStringAndSize($input, &buffer, &len);
    $1 = std::vector<uint8_t>((const unsigned char*)buffer,(const unsigned char*)buffer + len);
}

%typemap(out) std::vector<uint8_t> {
    PyBytes_FromStringAndSize(arg1.data(), arg1.size())
}
#endif


%catches (nabto::client::NabtoException) nabto::client::FutureVoid::waitForResult();
%catches (nabto::client::NabtoException) nabto::client::FutureVoid::getResult();
%catches (nabto::client::NabtoException) nabto::client::FutureBuffer::waitForResult();
%catches (nabto::client::NabtoException) nabto::client::FutureBuffer::getResult();
%catches (nabto::client::NabtoException) nabto::client::FutureMdnsResult::waitForResult();
%catches (nabto::client::NabtoException) nabto::client::FutureMdnsResult::getResult();
%catches (nabto::client::NabtoException) nabto::client::MdnsResult::getAddress();
%catches (nabto::client::NabtoException) nabto::client::MdnsResult::getPort();
%catches (nabto::client::NabtoException) nabto::client::MdnsResult::getDeviceId();
%catches (nabto::client::NabtoException) nabto::client::MdnsResult::getProductId();
%catches (nabto::client::NabtoException) nabto::client::TcpTunnel::open(uint16_t localPort, uint16_t remotePort);

%catches (nabto::client::NabtoException) nabto::client::Stream::open(uint32_t contentType);
%catches (nabto::client::NabtoException) nabto::client::Stream::readAll(size_t n);
%catches (nabto::client::NabtoException) nabto::client::Stream::readSome(size_t max);
%catches (nabto::client::NabtoException) nabto::client::Stream::write(std::vector<uint8_t> buffer);
%catches (nabto::client::NabtoException) nabto::client::Stream::close();
%catches (nabto::client::NabtoException) nabto::client::Coap::setRequestPayload(int contentFormat, const std::vector<uint8_t>& buffer);
%catches (nabto::client::NabtoException) nabto::client::Coap::getResponseStatusCode();
%catches (nabto::client::NabtoException) nabto::client::Coap::getResponseContentFormat();
%catches (nabto::client::NabtoException) nabto::client::Coap::getResponsePayload();
%catches (nabto::client::NabtoException) nabto::client::Connection::setProductId(const std::string& deviceId);
%catches (nabto::client::NabtoException) nabto::client::Connection::setDeviceId(const std::string& deviceId);
%catches (nabto::client::NabtoException) nabto::client::Connection::setServerKey(const std::string& serverKey);
%catches (nabto::client::NabtoException) nabto::client::Connection::setServerConnectToken(const std::string& serverConnectToken);

%catches (nabto::client::NabtoException) nabto::client::Connection::setApplicationName(const std::string& applicationName);
%catches (nabto::client::NabtoException) nabto::client::Connection::setApplicationVersion(const std::string& applicationVersion);

%catches (nabto::client::NabtoException) nabto::client::Connection::setServerUrl(const std::string& serverUrl);
%catches (nabto::client::NabtoException) nabto::client::Connection::setPrivateKey(const std::string& privateKey);
%catches (nabto::client::NabtoException) nabto::client::Connection::setOptions(const std::string& options);
%catches (nabto::client::NabtoException) nabto::client::Connection::getOptions();
%catches (nabto::client::NabtoException) nabto::client::Connection::getDeviceFingerprintHex();
%catches (nabto::client::NabtoException) nabto::client::Connection::getClientFingerprintHex();
%catches (nabto::client::NabtoException) nabto::client::Connection::getInfo();

%catches (nabto::client::NabtoException) nabto::client::Connection::enableDirectCandidates();
%catches (nabto::client::NabtoException) nabto::client::Connection::forceDirectCandidate();
%catches (nabto::client::NabtoException) nabto::client::Connection::addDirectCandidate(const std::string& hostname, uint16_t port);
%catches (nabto::client::NabtoException) nabto::client::Connection::endOfDirectCandidates();


%catches (nabto::client::NabtoException) nabto::client::Context::setLogger(std::shared_ptr<Logger> logger);
%catches (nabto::client::NabtoException) nabto::client::Context::setLogLevel(const std::string& logLevel);

#ifdef SWIGPYTHON
%typemap(throws) nabto::client::NabtoException %{
  PyErr_SetString(PyExc_RuntimeError, $1.what());
  SWIG_fail;
%}
#endif

#ifdef SWIGJAVA
// Allow C++ exceptions to be handled in Java
%typemap(throws, throws="com.nabto.edge.client.swig.NabtoException") nabto::client::NabtoException {
  jclass excep = jenv->FindClass("com/nabto/edge/client/swig/NabtoException");
  if (excep) {
      jmethodID constructor = jenv->GetMethodID(excep, "<init>", "(I)V");
      jobject object = jenv->NewObject(excep, constructor, $1.status().getErrorCode());

      jenv->Throw((jthrowable)object);
  }
  return $null;
}

// Force the CustomException Java class to extend java.lang.Exception
%typemap(javabase) nabto::client::NabtoException "java.lang.Exception";

// Override getMessage()
%typemap(javacode) nabto::client::NabtoException %{
  public String getMessage() {
    return what();
  }
%}
#endif


%include "nabto_client.hpp"

#ifdef SWIGJAVA
%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("nabto_client");
        System.loadLibrary("nabto_client_jni");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}
#endif
