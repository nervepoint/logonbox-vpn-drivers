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
        				
        				tar file: 'target/tools/logonbox-vpn-tools-linux-x64.tar.gz',
        				    glob: 'lbv*',  exclude: '*.txt', overwrite: true,
        				    compress: true, dir: 'tools/target'
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
                        
                        tar file: 'target/tools/logonbox-vpn-tools-macos-x64.tar.gz',
                            glob: 'lbv*',  exclude: '*.txt', overwrite: true,
                            compress: true, dir: 'tools/target'
					}
				}
				
				/*
				 * Windows installers
				 */
				stage ('Windows LogonBox VPN Drivers') {
					agent {
						label 'install4j && windows'
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
					 		  	bat 'mvn -U -P native-image clean package'
					 		}
        				}
                        
                        zip zipFile: 'target/tools/logonbox-vpn-tools-windows-x64.tar.gz',
                            glob: 'lbv*',  exclude: '*.txt', overwrite: true,
                            dir: 'tools/target'
					}
				}
			}
		}
		stage ('Deploy') {
			agent {
				label 'linux'
			}
			steps {
			
				script {
					/* Create full version number from Maven POM version and the
					   build number */
					def pom = readMavenPom file: 'pom.xml'
					pom_version_array = pom.version.split('\\.')
					suffix_array = pom_version_array[2].split('-')
					env.FULL_VERSION = pom_version_array[0] + '.' + pom_version_array[1] + "." + suffix_array[0] + "-${BUILD_NUMBER}"
					echo 'Full Maven Version ' + env.FULL_VERSION
				}
				
			}					
		}		
	}
}