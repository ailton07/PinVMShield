PinVMShield
===================

Original project: https://bitbucket.org/rjrodriguez/pinvmshield

Originals authors: 

- Rodriguez, Ricardo J.
- Rodriguez Gaston, Inaki
- Alonso, Javier

This project intends to be an update to the original PinVMShield project.

Este projeto faz parte de uma investigação inicial sobre Evasão de Instrumentadores Binários Dinâmicos. Projetos relacionados:
https://github.com/ailton07/TLS_DetectPin

----------


Updates
-------------
O projeto foi portado para o Visual Studio 2010, versão mais utilizada para realizar o build do Pin e de PinTools. A versão do Pin que o projeto usa os includes é a mais recente para Visual Studio, [revisão 71313](https://software.intel.com/en-us/articles/pintool-downloads).

----------

Requirements
-------------

- Visual Studio 
- Pin-2.14-71313-msvc10-windows

----------





How to Build
-------------
Para realizar o build, o projeto deve ter as dependecias corretamente configuradas. Seguem as configurações básicas, considerando que o diretório do PIN encontra-se em:
> F:\pin

**Configurações:**

> Additional Include Directories:
> Deve ter os valores: 
> **F:\pin\extras\xed-ia32\include;F:\pin\extras\components\include;F:\pin\source\include\pin\gen;F:\pin\source\include\pin;%(AdditionalIncludeDirectories)**

> ![Imgur](http://i.imgur.com/7Tq69dL.png)

> Additional Library Direcories:
> Deve ter os valores: 
> **F:\pin\ia32\lib-ext;F:\pin\extras\xed-ia32\lib;F:\pin\extras\components\lib\ia32;F:\pin\ia32\lib;%(AdditionalLibraryDirectories)**

> ![img](http://i.imgur.com/cPOa3HC.png)


----------

ChangeLog
-------------
>**16/04/17:**
>Alteração na API **PIN_CallApplicationFunction**.
>
```
Assinatura antiga:

VOID LEVEL_PINCLIENT::PIN_CallApplicationFunction	( 	const CONTEXT * 	ctxt,
THREADID 	tid,
CALLINGSTD_TYPE 	cstype,
AFUNPTR 	origFunPtr,
 	... ) 	
```

```
Assinatura nova:


VOID LEVEL_PINCLIENT::PIN_CallApplicationFunction	( 	const CONTEXT * 	ctxt,
THREADID 	tid,
CALLINGSTD_TYPE 	cstype,
AFUNPTR 	origFunPtr,
CALL_APPLICATION_FUNCTION_PARAM * 	param,
 	...
) 		
```

