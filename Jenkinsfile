pipeline {
 	agent none
 	tools {
		maven 'Maven 3.9.0' 
		jdk 'Graal JDK 21' 
	}

	stages {
		stage ('LogonBox VPN Drivers') {
			parallel {
			    /*
                 * Deploy cross platform libraries
                 */
                stage ('Cross-platform VPN Driver Libraries') {
                    agent {
                        label 'any'
                    }
                    steps {
                        configFileProvider([
                                configFile(
                                    fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
                                    replaceTokens: true,
                                    targetLocation: 'hypersocket.build.properties',
                                    variable: 'BUILD_PROPERTIES'
                                )
                            ]) {
                            withMaven(
                                globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
                            ) {
                                sh 'mvn -U clean deploy'
                            }
                        }
                    }
                }
                
				/*
				 * Linux Installers and Packages
				 */
				stage ('Linux 64 bit LogonBox VPN Drivers') {
					agent {
						label 'linux && x86_64'
					}
					steps {
                    
                        script {
                            env.FULL_VERSION = getFullVersion()
                            echo "Full Version : ${env.FULLVERSION}"
                        }
                        
						configFileProvider([
					 			configFile(
					 				fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
					 				replaceTokens: true,
					 				targetLocation: 'hypersocket.build.properties',
					 				variable: 'BUILD_PROPERTIES'
					 			)
					 		]) {
					 		withMaven(
					 			globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
					 		) {
					 		  	sh 'mvn -U -P native-image clean package'
					 		}
        				}
        				
        				tar file: 'target/logonbox-vpn-tools-linux-x64-' + env.FULL_VERSION + '.tar.gz',
        				    glob: 'lbv*',  exclude: '*.*', overwrite: true,
        				    compress: true, dir: 'tools/target'
                        
                        tar file: 'target/logonbox-vpn-library-linux-x64-' + env.FULL_VERSION + '.tar.gz',
                            glob: '*.so,*.h,*.txt,LICENSE',  exclude: 'libawt*,libjvm*,libjava*', overwrite: true,
                            compress: true, dir: 'dll/target/lib'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'target/*', 
                                storageClass: 'STANDARD', 
                                useServerSideEncryption: false]], 
                            pluginFailureResultConstraint: 'FAILURE', 
                            profileName: 'LogonBox Buckets', 
                            userMetadata: []
                        )
					}
				}
                
                /*
                 * Linux Installers and Packages
                 */
                stage ('Linux Arm 64 bit LogonBox VPN Drivers') {
                    agent {
                        label 'linux && aarch64'
                    }
                    steps {
                    
                        script {
                            env.FULL_VERSION = getFullVersion()
                            echo "Full Version : ${env.FULLVERSION}"
                        }
                        
                        configFileProvider([
                                configFile(
                                    fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
                                    replaceTokens: true,
                                    targetLocation: 'hypersocket.build.properties',
                                    variable: 'BUILD_PROPERTIES'
                                )
                            ]) {
                            withMaven(
                                globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
                            ) {
                                sh 'mvn -U -P native-image clean package'
                            }
                        }
                        
                        tar file: 'target/logonbox-vpn-tools-linux-aarch64-' + env.FULL_VERSION + '.tar.gz',
                            glob: 'lbv*',  exclude: '*.*', overwrite: true,
                            compress: true, dir: 'tools/target'
                        
                        tar file: 'target/logonbox-vpn-library-aarch64-x64-' + env.FULL_VERSION + '.tar.gz',
                            glob: '*.so,*.h,*.txt,LICENSE',  exclude: 'libawt*,libjvm*,libjava*', overwrite: true,
                            compress: true, dir: 'dll/target/lib'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'target/*', 
                                storageClass: 'STANDARD', 
                                useServerSideEncryption: false]], 
                            pluginFailureResultConstraint: 'FAILURE', 
                            profileName: 'LogonBox Buckets', 
                            userMetadata: []
                        )
                    }
                }
				
				/*
				 * MacOS installers
				 */
				stage ('Intel MacOS LogonBox VPN Drivers') {
					agent {
						label 'macos && x86_64'
					}
					steps {
                    
                        script {
                            env.FULL_VERSION = getFullVersion()
                            echo "Full Version : ${env.FULLVERSION}"
                        }
                        
						configFileProvider([
					 			configFile(
					 				fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
					 				replaceTokens: true,
					 				targetLocation: 'hypersocket.build.properties',
					 				variable: 'BUILD_PROPERTIES'
					 			)
					 		]) {
					 		withMaven(
					 			globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
					 		) {
                                sh 'mvn -U -P native-image clean package'
					 		}
        				}
                        
                        tar file: 'target/logonbox-vpn-tools-macos-x64-' + env.FULL_VERSION + '.tar.gz',
                            glob: 'lbv*',  exclude: '*.*', overwrite: true,
                            compress: true, dir: 'tools/target'
                            
                        tar file: 'target/logonbox-vpn-library-macos-x64-' + env.FULL_VERSION + '.tar.gz',
                            glob: '*.dylib,*.h,*.txt,LICENSE',  exclude: 'libawt*,libjvm*,libjava*', overwrite: true,
                            compress: true, dir: 'dll/target/lib'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'target/*', 
                                storageClass: 'STANDARD', 
                                useServerSideEncryption: false]], 
                            pluginFailureResultConstraint: 'FAILURE', 
                            profileName: 'LogonBox Buckets', 
                            userMetadata: []
                        )
					}
				}
                
                /*
                 * Arm MacOS installers
                 */
                stage ('Arm MacOS LogonBox VPN Drivers') {
                    agent {
                        label 'macos && aarch64'
                    }
                    steps {
                    
                        script {
                            env.FULL_VERSION = getFullVersion()
                            echo "Full Version : ${env.FULLVERSION}"
                        }
                        
                        configFileProvider([
                                configFile(
                                    fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
                                    replaceTokens: true,
                                    targetLocation: 'hypersocket.build.properties',
                                    variable: 'BUILD_PROPERTIES'
                                )
                            ]) {
                            withMaven(
                                globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
                            ) {
                                sh 'mvn -U -P native-image clean package'
                            }
                        }
                        
                        tar file: 'target/logonbox-vpn-tools-macos-aarch64-' + env.FULL_VERSION + '.tar.gz',
                            glob: 'lbv*',  exclude: '*.*', overwrite: true,
                            compress: true, dir: 'tools/target'
                            
                        tar file: 'target/logonbox-vpn-library-macos-aarch64-' + env.FULL_VERSION + '.tar.gz',
                            glob: '*.dylib,*.h,*.txt,LICENSE',  exclude: 'reports,libawt*,libjvm*,libjava*', overwrite: true,
                            compress: true, dir: 'dll/target/lib'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'target/*', 
                                storageClass: 'STANDARD', 
                                useServerSideEncryption: false]], 
                            pluginFailureResultConstraint: 'FAILURE', 
                            profileName: 'LogonBox Buckets', 
                            userMetadata: []
                        )
                    }
                }
				
				/*
				 * Windows installers
				 */
				stage ('Windows LogonBox VPN Drivers') {
				
				    /* TEMPORARY */
				    /* when { expression { false } } */
				    
					agent {
						label 'windows && x86_64'
					}
					steps {
                    
                        script {
                            env.FULL_VERSION = getFullVersion()
                            echo "Full Version : ${env.FULLVERSION}"
                        }
                        
						configFileProvider([
					 			configFile(
					 				fileId: 'bb62be43-6246-4ab5-9d7a-e1f35e056d69',  
					 				replaceTokens: true,
					 				targetLocation: 'hypersocket.build.properties',
					 				variable: 'BUILD_PROPERTIES'
					 			)
					 		]) {
					 		withMaven(
					 			globalMavenSettingsConfig: '4bc608a8-6e52-4765-bd72-4763f45bfbde'
					 		) {
					 		  	bat 'mvn -U -P native-image clean package'
					 		}
        				}
                        
                        zip zipFile: 'target/logonbox-vpn-tools-windows-x64-' + env.FULL_VERSION + '.zip',
                            glob: 'lbv*',  overwrite: true,
                            dir: 'tools/target'
                            
                        zip zipFile: 'target/logonbox-vpn-library-windows-x64-' + env.FULL_VERSION + '.zip',
                            glob: 'lbv*.dll,*.h',  exclude: 'reports,libawt*,libjvm*,libjava*', overwrite: true,
                            dir: '.'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'target/*', 
                                storageClass: 'STANDARD', 
                                useServerSideEncryption: false]], 
                            pluginFailureResultConstraint: 'FAILURE', 
                            profileName: 'LogonBox Buckets', 
                            userMetadata: []
                        )
					}
				}
			}
		}
	}
}

/* Create full version number from Maven POM version and the build number
 *
 * TODO make into a reusable library - https://stackoverflow.com/questions/47628248/how-to-create-methods-in-jenkins-declarative-pipeline
 */
String getFullVersion() {
    def pom = readMavenPom file: "pom.xml"
    pom_version_array = pom.version.split('\\.')
    suffix_array = pom_version_array[2].split('-')
    return pom_version_array[0] + '.' + pom_version_array[1] + "." + suffix_array[0] + "-${BUILD_NUMBER}"
}