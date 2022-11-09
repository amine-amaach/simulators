import cv2
import pyfirmata
from cvzone.HandTrackingModule import HandDetector


cap = cv2.VideoCapture(0)

if not cap.isOpened():
    print("Camera couldn't Access")
    exit()

detector = HandDetector(detectionCon=0.7)

pinR, pinY, pinG = 2, 3, 4
port = 'COM7' #Replace your port COM
board = pyfirmata.Arduino(port)


while cap.isOpened():
    success, img = cap.read()
    img = detector.findHands(img, draw=False)
    lmList, bbox = detector.findPosition(img, draw=False)

    if lmList:
        fingers = detector.fingersUp()
        thumb, index, pinky = fingers[0], fingers[1], fingers[4]
        thumbX, thumbY = lmList[4][0], lmList[4][1]
        indexX, indexY = lmList[8][0], lmList[8][1]
        pinkyX, pinkyY = lmList[20][0],lmList[20][1]

        if thumb == 1:
            cv2.circle(img, (thumbX,thumbY), 17, (0,0,255), cv2.FILLED)
        if index == 1:
            cv2.circle(img, (indexX, indexY), 17, (0, 255, 255), cv2.FILLED)
        if pinky == 1:
            cv2.circle(img, (pinkyX, pinkyY), 17, (0, 255, 0), cv2.FILLED)


        MetalFinger = [thumb, index, pinky]
        board.digital[pinR].write(thumb)
        board.digital[pinY].write(index)
        board.digital[pinG].write(pinky)


    cv2.imshow("Image", img)
    cv2.waitKey(1)
