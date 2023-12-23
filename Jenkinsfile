pipeline {
 	agent none
 	tools {
		maven 'Maven 3.9.0' 
		jdk 'Graal JDK 17' 
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
						label 'install4j && linux && x86_64'
					}
					steps {
                    
                        script {
                            env.FULLVERSION = getFullVersion()
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
        				
        				tar file: 'packages/logonbox-vpn-tools-linux-x64-' + env.FULL_VERSION + '.tar.gz',
        				    glob: 'lbv*',  exclude: '*.txt', overwrite: true,
        				    compress: true, dir: 'tools/target'
        				    
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'packages/*', 
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
				stage ('MacOS LogonBox VPN Drivers') {
					agent {
						label 'install4j && macos'
					}
					steps {
                    
                        script {
                            env.FULLVERSION = getFullVersion()
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
                        
                        tar file: 'packages/logonbox-vpn-tools-macos-x64-' + env.FULL_VERSION + '.tar.gz',
                            glob: 'lbv*',  exclude: '*.txt', overwrite: true,
                            compress: true, dir: 'tools/target'
                            
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'packages/*', 
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
				    when { expression { false } }
				    
					agent {
						label 'install4j && windows'
					}
					steps {
                    
                        script {
                            env.FULLVERSION = getFullVersion()
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
                        
                        zip zipFile: 'packages/logonbox-vpn-tools-windows-x64-' + env.FULL_VERSION + '.zip',
                            glob: 'lbv*',  exclude: '*.txt', overwrite: true,
                            dir: 'tools/target'
                
                        s3Upload(
                            consoleLogLevel: 'INFO', 
                            dontSetBuildResultOnFailure: false, 
                            dontWaitForConcurrentBuildCompletion: false, 
                            entries: [[
                                bucket: 'logonbox-packages/logonbox-vpn-drivers/' + env.FULL_VERSION, 
                                noUploadOnFailure: true, 
                                selectedRegion: 'eu-west-1', 
                                sourceFile: 'packages/*', 
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