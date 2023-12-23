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
				 * Linux Installers and Packages
				 */
				stage ('Linux LogonBox VPN Drivers') {
					agent {
						label 'install4j && linux'
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
					 		  	sh 'mvn -P native-image clean package'
					 		}
        				}
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
                                sh 'mvn -P native-image clean package'
					 		}
        				}
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
					 		  	bat 'mvn -P native-image clean package'
					 		}
        				}
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